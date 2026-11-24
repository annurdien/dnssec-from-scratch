use std::cmp::Ordering;
use std::fmt;

use crate::rdata::{RData, TYPE_OPT};

pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_NXDOMAIN: u8 = 3;

#[derive(Debug, Clone, Eq)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
}

impl DnsName {
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    pub fn from_labels(labels: Vec<Vec<u8>>) -> Self {
        Self { labels }
    }

    pub fn parse_str(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() || trimmed == "." {
            return Ok(Self::root());
        }
        let stripped = trimmed.strip_suffix('.').unwrap_or(trimmed);
        let mut labels = Vec::new();
        for part in stripped.split('.') {
            if part.is_empty() {
                return Err(format!("empty label in domain name: {input}"));
            }
            if part.len() > 63 {
                return Err(format!("label exceeds 63 bytes: {part}"));
            }
            labels.push(part.as_bytes().to_vec());
        }
        let name = Self { labels };
        if name.to_wire().len() > 255 {
            return Err(format!("domain name exceeds 255 wire bytes: {input}"));
        }
        Ok(name)
    }

    pub fn parse_wire(packet: &[u8], start_offset: usize) -> Result<(Self, usize), String> {
        let mut labels = Vec::new();
        let mut offset = start_offset;
        let mut consumed_end: Option<usize> = None;
        let mut jumps = 0usize;
        let mut total_wire_len = 0usize;

        loop {
            if offset >= packet.len() {
                return Err("unexpected EOF while reading DNS name".to_string());
            }
            let len = packet[offset];
            if len == 0 {
                if consumed_end.is_none() {
                    consumed_end = Some(offset + 1);
                }
                total_wire_len += 1;
                if total_wire_len > 255 {
                    return Err("DNS name exceeds 255 bytes".to_string());
                }
                break;
            }

            match len & 0xC0 {
                0xC0 => {
                    if offset + 1 >= packet.len() {
                        return Err("truncated compression pointer".to_string());
                    }
                    let ptr = (((len & 0x3F) as usize) << 8) | (packet[offset + 1] as usize);
                    if ptr >= packet.len() {
                        return Err(format!("compression pointer out of bounds: {ptr}"));
                    }
                    if consumed_end.is_none() {
                        consumed_end = Some(offset + 2);
                    }
                    jumps += 1;
                    if jumps > 64 {
                        return Err("compression pointer loop detected".to_string());
                    }
                    offset = ptr;
                }
                0x00 => {
                    let label_len = len as usize;
                    let end = offset + 1 + label_len;
                    if end > packet.len() {
                        return Err("truncated DNS label".to_string());
                    }
                    total_wire_len += 1 + label_len;
                    if total_wire_len > 255 {
                        return Err("DNS name exceeds 255 bytes".to_string());
                    }
                    labels.push(packet[offset + 1..end].to_vec());
                    offset = end;
                }
                _ => {
                    return Err(format!("unsupported DNS label type bits: 0x{len:02x}"));
                }
            }
        }

        Ok((Self { labels }, consumed_end.unwrap_or(offset + 1)))
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    pub fn parent(&self) -> Option<Self> {
        if self.labels.is_empty() {
            None
        } else {
            Some(Self {
                labels: self.labels[1..].to_vec(),
            })
        }
    }

    pub fn is_wildcard(&self) -> bool {
        matches!(self.labels.first(), Some(first) if first.as_slice() == b"*")
    }

    /// Label count per RFC 4034 Section 3.1.3: excludes root and any leading `*` wildcard label.
    pub fn rrsig_label_count(&self) -> u8 {
        let count = if self.is_wildcard() {
            self.labels.len().saturating_sub(1)
        } else {
            self.labels.len()
        };
        count as u8
    }

    /// Constructs `*.<rightmost `keep` labels>` for RFC 4035 Section 5.3.2 wildcard verification.
    pub fn wildcard_with_suffix_labels(&self, keep: usize) -> Option<Self> {
        if keep > self.labels.len() {
            return None;
        }
        let start = self.labels.len() - keep;
        let mut out = Vec::with_capacity(keep + 1);
        out.push(b"*".to_vec());
        out.extend_from_slice(&self.labels[start..]);
        Some(Self { labels: out })
    }

    /// Returns a child name prepended with a single label, e.g. `prepended(b"*")` -> `*.zone`.
    pub fn prepend_label(&self, label: &[u8]) -> Self {
        let mut labels = Vec::with_capacity(self.labels.len() + 1);
        labels.push(label.to_vec());
        labels.extend_from_slice(&self.labels);
        Self { labels }
    }

    pub fn is_subdomain_of(&self, zone: &Self) -> bool {
        if self.labels.len() < zone.labels.len() {
            return false;
        }
        let offset = self.labels.len() - zone.labels.len();
        self.labels[offset..]
            .iter()
            .zip(zone.labels.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Uncompressed wire format preserving original label byte case.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for label in &self.labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out
    }

    /// Canonical wire format per RFC 4034 Section 6.2: uncompressed and ASCII lowercased.
    pub fn to_canonical_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for label in &self.labels {
            out.push(label.len() as u8);
            for &b in label {
                out.push(b.to_ascii_lowercase());
            }
        }
        out.push(0);
        out
    }

    /// Canonical DNS name ordering per RFC 4034 Section 6.1 (rightmost label first, ASCII lowercase).
    pub fn canonical_cmp(&self, other: &Self) -> Ordering {
        let mut a_iter = self.labels.iter().rev();
        let mut b_iter = other.labels.iter().rev();

        loop {
            match (a_iter.next(), b_iter.next()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(la), Some(lb)) => {
                    for (&ba, &bb) in la.iter().zip(lb.iter()) {
                        let cmp = ba.to_ascii_lowercase().cmp(&bb.to_ascii_lowercase());
                        if cmp != Ordering::Equal {
                            return cmp;
                        }
                    }
                    let len_cmp = la.len().cmp(&lb.len());
                    if len_cmp != Ordering::Equal {
                        return len_cmp;
                    }
                }
            }
        }
    }
}

impl PartialEq for DnsName {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_cmp(other) == Ordering::Equal
    }
}

impl Ord for DnsName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

impl PartialOrd for DnsName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for DnsName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_canonical_wire().hash(state);
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return write!(f, ".");
        }
        for label in &self.labels {
            let s = String::from_utf8_lossy(label);
            write!(f, "{s}.")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    pub fn aa(&self) -> bool {
        (self.flags & 0x0400) != 0
    }

    pub fn tc(&self) -> bool {
        (self.flags & 0x0200) != 0
    }

    pub fn rd(&self) -> bool {
        (self.flags & 0x0100) != 0
    }

    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.qdcount.to_be_bytes());
        out.extend_from_slice(&self.ancount.to_be_bytes());
        out.extend_from_slice(&self.nscount.to_be_bytes());
        out.extend_from_slice(&self.arcount.to_be_bytes());
    }

    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 12 {
            return Err(format!("DNS header truncated ({} bytes)", buf.len()));
        }
        Ok(Self {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: DnsName,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: DnsName,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

impl Record {
    pub fn encode(&self, out: &mut Vec<u8>) {
        if let RData::Opt {
            udp_payload_size,
            extended_rcode,
            version,
            dnssec_ok,
            data,
        } = &self.rdata
        {
            out.push(0); // root owner name
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&udp_payload_size.to_be_bytes());
            let mut ttl_bytes = [*extended_rcode, *version, 0, 0];
            if *dnssec_ok {
                ttl_bytes[2] |= 0x80;
            }
            out.extend_from_slice(&ttl_bytes);
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
            return;
        }

        out.extend_from_slice(&self.name.to_wire());
        out.extend_from_slice(&self.rtype.to_be_bytes());
        out.extend_from_slice(&self.rclass.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let rdata_wire = self.rdata.to_wire();
        out.extend_from_slice(&(rdata_wire.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata_wire);
    }

    pub fn parse(packet: &[u8], offset: usize) -> Result<(Self, usize), String> {
        let (name, mut pos) = DnsName::parse_wire(packet, offset)?;
        if pos + 10 > packet.len() {
            return Err("truncated DNS resource record header".to_string());
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > packet.len() {
            return Err(format!(
                "truncated RDATA for type {rtype} (need {rdlength}, have {})",
                packet.len() - pos
            ));
        }

        let rdata = if rtype == TYPE_OPT {
            let ttl_bytes = ttl.to_be_bytes();
            RData::Opt {
                udp_payload_size: rclass,
                extended_rcode: ttl_bytes[0],
                version: ttl_bytes[1],
                dnssec_ok: (ttl_bytes[2] & 0x80) != 0,
                data: packet[pos..pos + rdlength].to_vec(),
            }
        } else {
            RData::parse(rtype, packet, pos, rdlength)?
        };

        Ok((
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            pos + rdlength,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    pub fn build_query(
        id: u16,
        name: DnsName,
        qtype: u16,
        recursion_desired: bool,
        edns_udp_size: u16,
    ) -> Self {
        let mut flags = 0u16;
        if recursion_desired {
            flags |= 0x0100;
        }
        let opt = Record {
            name: DnsName::root(),
            rtype: TYPE_OPT,
            rclass: edns_udp_size,
            ttl: 0x0000_8000,
            rdata: RData::Opt {
                udp_payload_size: edns_udp_size,
                extended_rcode: 0,
                version: 0,
                dnssec_ok: true,
                data: Vec::new(),
            },
        };
        Self {
            header: Header {
                id,
                flags,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 1,
            },
            questions: vec![Question {
                name,
                qtype,
                qclass: CLASS_IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: vec![opt],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        let header = Header {
            id: self.header.id,
            flags: self.header.flags,
            qdcount: self.questions.len() as u16,
            ancount: self.answers.len() as u16,
            nscount: self.authorities.len() as u16,
            arcount: self.additionals.len() as u16,
        };
        header.encode(&mut out);

        for q in &self.questions {
            out.extend_from_slice(&q.name.to_wire());
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for r in &self.answers {
            r.encode(&mut out);
        }
        for r in &self.authorities {
            r.encode(&mut out);
        }
        for r in &self.additionals {
            r.encode(&mut out);
        }
        out
    }

    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        let header = Header::parse(packet)?;
        let mut pos = 12usize;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let (name, next_pos) = DnsName::parse_wire(packet, pos)?;
            pos = next_pos;
            if pos + 4 > packet.len() {
                return Err("truncated DNS question".to_string());
            }
            let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
            let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
            pos += 4;
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            let (rec, next_pos) = Record::parse(packet, pos)?;
            pos = next_pos;
            answers.push(rec);
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            let (rec, next_pos) = Record::parse(packet, pos)?;
            pos = next_pos;
            authorities.push(rec);
        }

        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            let (rec, next_pos) = Record::parse(packet, pos)?;
            pos = next_pos;
            additionals.push(rec);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn extended_rcode(&self) -> u16 {
        let base = self.header.rcode() as u16;
        for rr in &self.additionals {
            if let RData::Opt { extended_rcode, .. } = rr.rdata {
                return ((extended_rcode as u16) << 4) | base;
            }
        }
        base
    }
}

pub fn rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_name_ordering_matches_rfc4034_example() {
        // RFC 4034 Section 6.1 canonical order test vector
        let ordered = [
            "example",
            "a.example",
            "yljkjljk.a.example",
            "Z.a.example",
            "zABC.a.EXAMPLE",
            "z.example",
            "*.z.example",
            "example.net",
        ];
        let mut parsed: Vec<DnsName> = ordered
            .iter()
            .rev()
            .map(|s| DnsName::parse_str(s).unwrap())
            .collect();
        parsed.sort();
        let expected: Vec<DnsName> = ordered
            .iter()
            .map(|s| DnsName::parse_str(s).unwrap())
            .collect();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn pointer_compression_decodes_cleanly() {
        // Packet with "example.com." at offset 12 and pointer to "com." at offset 20
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&[7]);
        pkt.extend_from_slice(b"example");
        pkt.extend_from_slice(&[3]);
        pkt.extend_from_slice(b"com");
        pkt.push(0);
        let ptr_start = pkt.len();
        pkt.extend_from_slice(&[3]);
        pkt.extend_from_slice(b"www");
        pkt.extend_from_slice(&[0xC0, 12]);

        let (name, end) = DnsName::parse_wire(&pkt, ptr_start).unwrap();
        assert_eq!(name.to_string(), "www.example.com.");
        assert_eq!(end, pkt.len());
    }

    #[test]
    fn pointer_loop_is_rejected() {
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&[0xC0, 12]);
        assert!(DnsName::parse_wire(&pkt, 12).is_err());
    }
}
