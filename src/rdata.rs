use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::wire::DnsName;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_DNAME: u16 = 39;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_DS: u16 = 43;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_NSEC3: u16 = 50;
pub const TYPE_NSEC3PARAM: u16 = 51;
pub const TYPE_CAA: u16 = 257;

pub fn type_name(rtype: u16) -> String {
    match rtype {
        TYPE_A => "A".to_string(),
        TYPE_NS => "NS".to_string(),
        TYPE_CNAME => "CNAME".to_string(),
        TYPE_SOA => "SOA".to_string(),
        TYPE_PTR => "PTR".to_string(),
        TYPE_MX => "MX".to_string(),
        TYPE_TXT => "TXT".to_string(),
        TYPE_AAAA => "AAAA".to_string(),
        TYPE_SRV => "SRV".to_string(),
        TYPE_DNAME => "DNAME".to_string(),
        TYPE_OPT => "OPT".to_string(),
        TYPE_DS => "DS".to_string(),
        TYPE_RRSIG => "RRSIG".to_string(),
        TYPE_NSEC => "NSEC".to_string(),
        TYPE_DNSKEY => "DNSKEY".to_string(),
        TYPE_NSEC3 => "NSEC3".to_string(),
        TYPE_NSEC3PARAM => "NSEC3PARAM".to_string(),
        TYPE_CAA => "CAA".to_string(),
        other => format!("TYPE{other}"),
    }
}

pub fn parse_qtype(s: &str) -> Result<u16, String> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Ok(TYPE_A),
        "NS" => Ok(TYPE_NS),
        "CNAME" => Ok(TYPE_CNAME),
        "SOA" => Ok(TYPE_SOA),
        "PTR" => Ok(TYPE_PTR),
        "MX" => Ok(TYPE_MX),
        "TXT" => Ok(TYPE_TXT),
        "AAAA" => Ok(TYPE_AAAA),
        "SRV" => Ok(TYPE_SRV),
        "DS" => Ok(TYPE_DS),
        "RRSIG" => Ok(TYPE_RRSIG),
        "NSEC" => Ok(TYPE_NSEC),
        "DNSKEY" => Ok(TYPE_DNSKEY),
        "NSEC3" => Ok(TYPE_NSEC3),
        "CAA" => Ok(TYPE_CAA),
        other => other
            .parse::<u16>()
            .map_err(|_| format!("unsupported record type: {s}")),
    }
}

pub fn algorithm_name(alg: u8) -> &'static str {
    match alg {
        5 => "RSASHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        _ => "UNKNOWN",
    }
}

pub fn digest_type_name(dtype: u8) -> &'static str {
    match dtype {
        1 => "SHA-1",
        2 => "SHA-256",
        4 => "SHA-384",
        _ => "UNKNOWN",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnskeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl DnskeyData {
    pub fn is_zone_key(&self) -> bool {
        (self.flags & 0x0100) != 0
    }

    pub fn is_sep(&self) -> bool {
        (self.flags & 0x0001) != 0
    }

    pub fn is_revoked(&self) -> bool {
        (self.flags & 0x0080) != 0
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.public_key.len());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.push(self.protocol);
        out.push(self.algorithm);
        out.extend_from_slice(&self.public_key);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl DsData {
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.digest.len());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.push(self.algorithm);
        out.push(self.digest_type);
        out.extend_from_slice(&self.digest);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsigData {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer_name: DnsName,
    pub signature: Vec<u8>,
}

impl RrsigData {
    /// RRSIG RDATA prefix without signature, with canonical lowercased signer name (RFC 4034 Section 3.1.8.1).
    pub fn signed_prefix_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + 64);
        out.extend_from_slice(&self.type_covered.to_be_bytes());
        out.push(self.algorithm);
        out.push(self.labels);
        out.extend_from_slice(&self.original_ttl.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out.extend_from_slice(&self.inception.to_be_bytes());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.extend_from_slice(&self.signer_name.to_canonical_wire());
        out
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = self.signed_prefix_wire();
        out.extend_from_slice(&self.signature);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsecData {
    pub next_domain_name: DnsName,
    pub types: Vec<u16>,
    pub raw_type_bitmaps: Vec<u8>,
}

impl NsecData {
    pub fn new(next_domain_name: DnsName, types: Vec<u16>) -> Self {
        let raw_type_bitmaps = encode_type_bitmaps(&types);
        Self {
            next_domain_name,
            types,
            raw_type_bitmaps,
        }
    }

    pub fn has_type(&self, rtype: u16) -> bool {
        self.types.contains(&rtype)
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = self.next_domain_name.to_wire();
        out.extend_from_slice(&self.raw_type_bitmaps);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Data {
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed_owner: Vec<u8>,
    pub types: Vec<u16>,
    pub raw_type_bitmaps: Vec<u8>,
}

impl Nsec3Data {
    pub fn new(
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner: Vec<u8>,
        types: Vec<u16>,
    ) -> Self {
        let raw_type_bitmaps = encode_type_bitmaps(&types);
        Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            types,
            raw_type_bitmaps,
        }
    }

    pub fn has_type(&self, rtype: u16) -> bool {
        self.types.contains(&rtype)
    }

    pub fn opt_out(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.hash_algorithm);
        out.push(self.flags);
        out.extend_from_slice(&self.iterations.to_be_bytes());
        out.push(self.salt.len() as u8);
        out.extend_from_slice(&self.salt);
        out.push(self.next_hashed_owner.len() as u8);
        out.extend_from_slice(&self.next_hashed_owner);
        out.extend_from_slice(&self.raw_type_bitmaps);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Ns(DnsName),
    Cname(DnsName),
    Ptr(DnsName),
    Dname(DnsName),
    Soa {
        mname: DnsName,
        rname: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Mx {
        preference: u16,
        exchange: DnsName,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    Txt(Vec<Vec<u8>>),
    Dnskey(DnskeyData),
    Ds(DsData),
    Rrsig(RrsigData),
    Nsec(NsecData),
    Nsec3(Nsec3Data),
    Opt {
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        data: Vec<u8>,
    },
    Unknown {
        rtype: u16,
        data: Vec<u8>,
    },
}

impl RData {
    pub fn parse(rtype: u16, packet: &[u8], offset: usize, rdlength: usize) -> Result<Self, String> {
        let end = offset + rdlength;
        let slice = &packet[offset..end];

        match rtype {
            TYPE_A => {
                if rdlength != 4 {
                    return Err(format!("invalid A record length: {rdlength}"));
                }
                Ok(Self::A(Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3])))
            }
            TYPE_AAAA => {
                if rdlength != 16 {
                    return Err(format!("invalid AAAA record length: {rdlength}"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(slice);
                Ok(Self::AAAA(Ipv6Addr::from(octets)))
            }
            TYPE_NS => {
                let (name, _) = DnsName::parse_wire(packet, offset)?;
                Ok(Self::Ns(name))
            }
            TYPE_CNAME => {
                let (name, _) = DnsName::parse_wire(packet, offset)?;
                Ok(Self::Cname(name))
            }
            TYPE_PTR => {
                let (name, _) = DnsName::parse_wire(packet, offset)?;
                Ok(Self::Ptr(name))
            }
            TYPE_DNAME => {
                let (name, _) = DnsName::parse_wire(packet, offset)?;
                Ok(Self::Dname(name))
            }
            TYPE_SOA => {
                let (mname, pos) = DnsName::parse_wire(packet, offset)?;
                let (rname, pos) = DnsName::parse_wire(packet, pos)?;
                if pos + 20 > end {
                    return Err("truncated SOA RDATA".to_string());
                }
                Ok(Self::Soa {
                    mname,
                    rname,
                    serial: u32::from_be_bytes([packet[pos], packet[pos + 1], packet[pos + 2], packet[pos + 3]]),
                    refresh: u32::from_be_bytes([packet[pos + 4], packet[pos + 5], packet[pos + 6], packet[pos + 7]]),
                    retry: u32::from_be_bytes([packet[pos + 8], packet[pos + 9], packet[pos + 10], packet[pos + 11]]),
                    expire: u32::from_be_bytes([packet[pos + 12], packet[pos + 13], packet[pos + 14], packet[pos + 15]]),
                    minimum: u32::from_be_bytes([packet[pos + 16], packet[pos + 17], packet[pos + 18], packet[pos + 19]]),
                })
            }
            TYPE_MX => {
                if rdlength < 3 {
                    return Err("truncated MX RDATA".to_string());
                }
                let preference = u16::from_be_bytes([slice[0], slice[1]]);
                let (exchange, _) = DnsName::parse_wire(packet, offset + 2)?;
                Ok(Self::Mx {
                    preference,
                    exchange,
                })
            }
            TYPE_SRV => {
                if rdlength < 7 {
                    return Err("truncated SRV RDATA".to_string());
                }
                let priority = u16::from_be_bytes([slice[0], slice[1]]);
                let weight = u16::from_be_bytes([slice[2], slice[3]]);
                let port = u16::from_be_bytes([slice[4], slice[5]]);
                let (target, _) = DnsName::parse_wire(packet, offset + 6)?;
                Ok(Self::Srv {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
            TYPE_TXT => {
                let mut chunks = Vec::new();
                let mut i = 0;
                while i < slice.len() {
                    let len = slice[i] as usize;
                    i += 1;
                    if i + len > slice.len() {
                        return Err("truncated TXT character string".to_string());
                    }
                    chunks.push(slice[i..i + len].to_vec());
                    i += len;
                }
                Ok(Self::Txt(chunks))
            }
            TYPE_DNSKEY => {
                if rdlength < 4 {
                    return Err("truncated DNSKEY RDATA".to_string());
                }
                Ok(Self::Dnskey(DnskeyData {
                    flags: u16::from_be_bytes([slice[0], slice[1]]),
                    protocol: slice[2],
                    algorithm: slice[3],
                    public_key: slice[4..].to_vec(),
                }))
            }
            TYPE_DS => {
                if rdlength < 5 {
                    return Err("truncated DS RDATA".to_string());
                }
                Ok(Self::Ds(DsData {
                    key_tag: u16::from_be_bytes([slice[0], slice[1]]),
                    algorithm: slice[2],
                    digest_type: slice[3],
                    digest: slice[4..].to_vec(),
                }))
            }
            TYPE_RRSIG => {
                if rdlength < 19 {
                    return Err("truncated RRSIG RDATA".to_string());
                }
                let type_covered = u16::from_be_bytes([slice[0], slice[1]]);
                let algorithm = slice[2];
                let labels = slice[3];
                let original_ttl = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]);
                let expiration = u32::from_be_bytes([slice[8], slice[9], slice[10], slice[11]]);
                let inception = u32::from_be_bytes([slice[12], slice[13], slice[14], slice[15]]);
                let key_tag = u16::from_be_bytes([slice[16], slice[17]]);
                let (signer_name, sig_start) = DnsName::parse_wire(packet, offset + 18)?;
                if sig_start > end {
                    return Err("RRSIG signer name overflows RDATA".to_string());
                }
                Ok(Self::Rrsig(RrsigData {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer_name,
                    signature: packet[sig_start..end].to_vec(),
                }))
            }
            TYPE_NSEC => {
                let (next_domain_name, bitmap_start) = DnsName::parse_wire(packet, offset)?;
                if bitmap_start > end {
                    return Err("NSEC next domain name overflows RDATA".to_string());
                }
                let raw_type_bitmaps = packet[bitmap_start..end].to_vec();
                let types = decode_type_bitmaps(&raw_type_bitmaps)?;
                Ok(Self::Nsec(NsecData {
                    next_domain_name,
                    types,
                    raw_type_bitmaps,
                }))
            }
            TYPE_NSEC3 => {
                if rdlength < 6 {
                    return Err("truncated NSEC3 RDATA".to_string());
                }
                let hash_algorithm = slice[0];
                let flags = slice[1];
                let iterations = u16::from_be_bytes([slice[2], slice[3]]);
                let salt_len = slice[4] as usize;
                let mut pos = 5;
                if pos + salt_len >= rdlength {
                    return Err("truncated NSEC3 salt".to_string());
                }
                let salt = slice[pos..pos + salt_len].to_vec();
                pos += salt_len;
                let hash_len = slice[pos] as usize;
                pos += 1;
                if pos + hash_len > rdlength {
                    return Err("truncated NSEC3 next hashed owner".to_string());
                }
                let next_hashed_owner = slice[pos..pos + hash_len].to_vec();
                pos += hash_len;
                let raw_type_bitmaps = slice[pos..].to_vec();
                let types = decode_type_bitmaps(&raw_type_bitmaps)?;
                Ok(Self::Nsec3(Nsec3Data {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner,
                    types,
                    raw_type_bitmaps,
                }))
            }
            _ => Ok(Self::Unknown {
                rtype,
                data: slice.to_vec(),
            }),
        }
    }

    pub fn to_wire(&self) -> Vec<u8> {
        match self {
            Self::A(ip) => ip.octets().to_vec(),
            Self::AAAA(ip) => ip.octets().to_vec(),
            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) | Self::Dname(n) => n.to_wire(),
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut out = mname.to_wire();
                out.extend_from_slice(&rname.to_wire());
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
                out
            }
            Self::Mx {
                preference,
                exchange,
            } => {
                let mut out = preference.to_be_bytes().to_vec();
                out.extend_from_slice(&exchange.to_wire());
                out
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(&target.to_wire());
                out
            }
            Self::Txt(chunks) => {
                let mut out = Vec::new();
                for c in chunks {
                    out.push(c.len() as u8);
                    out.extend_from_slice(c);
                }
                out
            }
            Self::Dnskey(k) => k.to_wire(),
            Self::Ds(d) => d.to_wire(),
            Self::Rrsig(s) => s.to_wire(),
            Self::Nsec(n) => n.to_wire(),
            Self::Nsec3(n) => n.to_wire(),
            Self::Opt { data, .. } => data.clone(),
            Self::Unknown { data, .. } => data.clone(),
        }
    }

    /// Canonical RDATA per RFC 4034 Section 6.2 and RFC 6840 Section 5.1.
    /// Legacy embedded domain names (NS, CNAME, PTR, SOA, MX, SRV, DNAME, RRSIG) are uncompressed
    /// and lowercased. NSEC next_domain_name is uncompressed without forced lowercasing.
    pub fn to_canonical_rdata(&self) -> Vec<u8> {
        match self {
            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) | Self::Dname(n) => n.to_canonical_wire(),
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut out = mname.to_canonical_wire();
                out.extend_from_slice(&rname.to_canonical_wire());
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
                out
            }
            Self::Mx {
                preference,
                exchange,
            } => {
                let mut out = preference.to_be_bytes().to_vec();
                out.extend_from_slice(&exchange.to_canonical_wire());
                out
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(&target.to_canonical_wire());
                out
            }
            Self::Rrsig(s) => s.to_wire(),
            _ => self.to_wire(),
        }
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(ip) => write!(f, "{ip}"),
            Self::AAAA(ip) => write!(f, "{ip}"),
            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) | Self::Dname(n) => write!(f, "{n}"),
            Self::Soa {
                mname,
                rname,
                serial,
                ..
            } => write!(f, "{mname} {rname} {serial}"),
            Self::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {target}"),
            Self::Txt(chunks) => {
                for (i, c) in chunks.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "\"{}\"", String::from_utf8_lossy(c))?;
                }
                Ok(())
            }
            Self::Dnskey(k) => write!(
                f,
                "flags={} proto={} alg={}({}) key_len={}",
                k.flags,
                k.protocol,
                k.algorithm,
                algorithm_name(k.algorithm),
                k.public_key.len()
            ),
            Self::Ds(d) => write!(
                f,
                "tag={} alg={}({}) digest={}({}) {}",
                d.key_tag,
                d.algorithm,
                algorithm_name(d.algorithm),
                d.digest_type,
                digest_type_name(d.digest_type),
                hex_upper(&d.digest)
            ),
            Self::Rrsig(s) => write!(
                f,
                "covers={} alg={} labels={} tag={} signer={}",
                type_name(s.type_covered),
                s.algorithm,
                s.labels,
                s.key_tag,
                s.signer_name
            ),
            Self::Nsec(n) => {
                let types: Vec<String> = n.types.iter().map(|&t| type_name(t)).collect();
                write!(f, "next={} types=[{}]", n.next_domain_name, types.join(" "))
            }
            Self::Nsec3(n) => {
                let types: Vec<String> = n.types.iter().map(|&t| type_name(t)).collect();
                write!(
                    f,
                    "alg={} flags={} iter={} salt={} next={} types=[{}]",
                    n.hash_algorithm,
                    n.flags,
                    n.iterations,
                    if n.salt.is_empty() {
                        "-".to_string()
                    } else {
                        hex_upper(&n.salt)
                    },
                    crate::nsec::base32hex_encode(&n.next_hashed_owner),
                    types.join(" ")
                )
            }
            Self::Opt {
                udp_payload_size,
                dnssec_ok,
                ..
            } => write!(f, "EDNS0 udp={udp_payload_size} DO={dnssec_ok}"),
            Self::Unknown { rtype, data } => {
                write!(f, "TYPE{rtype} ({} bytes)", data.len())
            }
        }
    }
}

pub fn decode_type_bitmaps(buf: &[u8]) -> Result<Vec<u16>, String> {
    let mut types = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if pos + 2 > buf.len() {
            return Err("truncated NSEC type bitmap window header".to_string());
        }
        let window = buf[pos] as u16;
        let len = buf[pos + 1] as usize;
        pos += 2;
        if len == 0 || len > 32 || pos + len > buf.len() {
            return Err(format!("invalid NSEC type bitmap length: {len}"));
        }
        for (byte_idx, &byte) in buf[pos..pos + len].iter().enumerate() {
            for bit in 0..8 {
                if (byte & (0x80 >> bit)) != 0 {
                    let rtype = (window << 8) | ((byte_idx * 8 + bit) as u16);
                    types.push(rtype);
                }
            }
        }
        pos += len;
    }
    Ok(types)
}

pub fn encode_type_bitmaps(types: &[u16]) -> Vec<u8> {
    let mut sorted = types.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let window = (sorted[i] >> 8) as u8;
        let mut bitmap = [0u8; 32];
        let mut max_byte = 0usize;

        while i < sorted.len() && (sorted[i] >> 8) as u8 == window {
            let low = (sorted[i] & 0xFF) as usize;
            let byte_idx = low / 8;
            let bit = low % 8;
            bitmap[byte_idx] |= 0x80 >> bit;
            if byte_idx > max_byte {
                max_byte = byte_idx;
            }
            i += 1;
        }

        let len = max_byte + 1;
        out.push(window);
        out.push(len as u8);
        out.extend_from_slice(&bitmap[..len]);
    }
    out
}

pub fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02X}");
    }
    out
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for pair in clean.as_bytes().chunks(2) {
        let hex_str = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        let val = u8::from_str_radix(hex_str, 16)
            .map_err(|_| format!("invalid hex byte: {hex_str}"))?;
        out.push(val);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_bitmap_round_trip() {
        let types = vec![TYPE_A, TYPE_NS, TYPE_SOA, TYPE_RRSIG, TYPE_NSEC, TYPE_DNSKEY, TYPE_CAA];
        let encoded = encode_type_bitmaps(&types);
        let decoded = decode_type_bitmaps(&encoded).unwrap();
        assert_eq!(decoded, types);
    }
}
