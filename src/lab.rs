use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::signature::EcdsaKeyPair;

use crate::crypto::{generate_ecdsa_p256_key, make_ds, sign_rrset_ecdsa_p256};
use crate::nsec::{base32hex_encode, nsec3_hash};
use crate::rdata::{
    DnskeyData, DsData, Nsec3Data, NsecData, RData, TYPE_A, TYPE_DNSKEY, TYPE_DS, TYPE_NS,
    TYPE_NSEC, TYPE_NSEC3, TYPE_RRSIG, TYPE_SOA,
};
use crate::resolver::{DnssecResolver, SecurityStatus, ValidationResult};
use crate::wire::{
    DnsName, Header, Message, Record, CLASS_IN, RCODE_NOERROR, RCODE_NXDOMAIN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabMode {
    Valid,
    TamperIp,
    StripRrsig,
    ExpiredSig,
    BadDs,
    StripDs,
    UnsignedZone,
    Nsec3,
}

impl LabMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "valid" => Ok(Self::Valid),
            "tamper-ip" => Ok(Self::TamperIp),
            "strip-rrsig" => Ok(Self::StripRrsig),
            "expired-sig" => Ok(Self::ExpiredSig),
            "bad-ds" => Ok(Self::BadDs),
            "strip-ds" => Ok(Self::StripDs),
            "unsigned" => Ok(Self::UnsignedZone),
            "nsec3" => Ok(Self::Nsec3),
            other => Err(format!(
                "unknown lab mode '{other}' (expected: valid, tamper-ip, strip-rrsig, expired-sig, bad-ds, strip-ds, unsigned, nsec3)"
            )),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::TamperIp => "tamper-ip",
            Self::StripRrsig => "strip-rrsig",
            Self::ExpiredSig => "expired-sig",
            Self::BadDs => "bad-ds",
            Self::StripDs => "strip-ds",
            Self::UnsignedZone => "unsigned",
            Self::Nsec3 => "nsec3",
        }
    }
}

struct ZoneKeys {
    ksk_kp: EcdsaKeyPair,
    ksk_pub: DnskeyData,
    zsk_kp: EcdsaKeyPair,
    zsk_pub: DnskeyData,
}

impl ZoneKeys {
    fn generate() -> Result<Self, String> {
        let (ksk_kp, ksk_pub) = generate_ecdsa_p256_key(true)?;
        let (zsk_kp, zsk_pub) = generate_ecdsa_p256_key(false)?;
        Ok(Self {
            ksk_kp,
            ksk_pub,
            zsk_kp,
            zsk_pub,
        })
    }

    fn dnskey_records(&self, zone: &DnsName) -> Vec<Record> {
        vec![
            Record {
                name: zone.clone(),
                rtype: TYPE_DNSKEY,
                rclass: CLASS_IN,
                ttl: 3600,
                rdata: RData::Dnskey(self.ksk_pub.clone()),
            },
            Record {
                name: zone.clone(),
                rtype: TYPE_DNSKEY,
                rclass: CLASS_IN,
                ttl: 3600,
                rdata: RData::Dnskey(self.zsk_pub.clone()),
            },
        ]
    }
}

pub struct LocalLab {
    pub root_addr: SocketAddr,
    pub leaf_addr: SocketAddr,
    pub root_trust_anchor: DsData,
    stop: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl LocalLab {
    pub fn start(mode: LabMode) -> Result<Self, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1_760_000_000);
        let inception = now.saturating_sub(3600);
        let expiration = now + 86_400;

        let root_zone = DnsName::root();
        let leaf_zone = DnsName::parse_str("lab.test.")?;
        let leaf_ns = DnsName::parse_str("ns1.lab.test.")?;

        let root_keys = ZoneKeys::generate()?;
        let leaf_keys = ZoneKeys::generate()?;

        let root_trust_anchor = make_ds(&root_zone, &root_keys.ksk_pub, 2)?;
        let mut leaf_ds = make_ds(&leaf_zone, &leaf_keys.ksk_pub, 2)?;
        if mode == LabMode::BadDs {
            // Flip the first byte of the SHA-256 DS digest to simulate a mismatched delegation
            leaf_ds.digest[0] ^= 0xFF;
        }

        let root_udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let root_addr = root_udp.local_addr().map_err(|e| e.to_string())?;
        let root_tcp = TcpListener::bind(root_addr).map_err(|e| e.to_string())?;

        let leaf_udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let leaf_addr = leaf_udp.local_addr().map_err(|e| e.to_string())?;
        let leaf_tcp = TcpListener::bind(leaf_addr).map_err(|e| e.to_string())?;

        let root_state = Arc::new(RootState {
            zone: root_zone,
            leaf_zone: leaf_zone.clone(),
            leaf_ns: leaf_ns.clone(),
            keys: root_keys,
            leaf_ds,
            mode,
            inception,
            expiration,
        });

        let leaf_state = Arc::new(LeafState::build(
            leaf_zone,
            leaf_ns,
            leaf_keys,
            mode,
            inception,
            expiration,
            now,
        )?);

        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        handles.push(spawn_udp_server(
            root_udp,
            stop.clone(),
            {
                let st = root_state.clone();
                move |q| st.handle_query(q)
            },
        ));
        handles.push(spawn_tcp_server(
            root_tcp,
            stop.clone(),
            move |q| root_state.handle_query(q),
        ));
        handles.push(spawn_udp_server(
            leaf_udp,
            stop.clone(),
            {
                let st = leaf_state.clone();
                move |q| st.handle_query(q)
            },
        ));
        handles.push(spawn_tcp_server(
            leaf_tcp,
            stop.clone(),
            move |q| leaf_state.handle_query(q),
        ));

        Ok(Self {
            root_addr,
            leaf_addr,
            root_trust_anchor,
            stop,
            handles,
        })
    }

    pub fn resolver(&self) -> DnssecResolver {
        let mut ns_overrides = HashMap::new();
        ns_overrides.insert(DnsName::parse_str("ns1.lab.test.").unwrap(), self.leaf_addr);
        DnssecResolver {
            root_servers: vec![self.root_addr],
            root_anchors: vec![self.root_trust_anchor.clone()],
            ns_overrides,
            ..DnssecResolver::default()
        }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for LocalLab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct RootState {
    zone: DnsName,
    leaf_zone: DnsName,
    leaf_ns: DnsName,
    keys: ZoneKeys,
    leaf_ds: DsData,
    mode: LabMode,
    inception: u32,
    expiration: u32,
}

impl RootState {
    fn handle_query(&self, req: &Message) -> Message {
        let q = match req.questions.first() {
            Some(q) => q.clone(),
            None => return empty_response(req, RCODE_NOERROR, true),
        };

        // Answer root DNSKEY
        if q.name == self.zone && q.qtype == TYPE_DNSKEY {
            let mut answers = self.keys.dnskey_records(&self.zone);
            let sig = sign_rrset_ecdsa_p256(
                &answers,
                &self.zone,
                &self.keys.ksk_kp,
                &self.keys.ksk_pub,
                self.inception,
                self.expiration,
            )
            .unwrap();
            answers.push(sig);
            return build_response(req, RCODE_NOERROR, true, answers, Vec::new(), Vec::new());
        }

        // Delegate lab.test. (and anything beneath it)
        if q.name.is_subdomain_of(&self.leaf_zone) {
            let ns_rec = Record {
                name: self.leaf_zone.clone(),
                rtype: TYPE_NS,
                rclass: CLASS_IN,
                ttl: 300,
                rdata: RData::Ns(self.leaf_ns.clone()),
            };
            let glue = Record {
                name: self.leaf_ns.clone(),
                rtype: TYPE_A,
                rclass: CLASS_IN,
                ttl: 300,
                rdata: RData::A(Ipv4Addr::LOCALHOST),
            };

            let mut authorities = vec![ns_rec];

            match self.mode {
                LabMode::StripDs => {
                    // Simulate MITM stripping both DS and NSEC proof
                }
                LabMode::UnsignedZone => {
                    // Legitimate unsigned delegation: include signed NSEC at lab.test. with NS only (no DS)
                    let nsec = Record {
                        name: self.leaf_zone.clone(),
                        rtype: TYPE_NSEC,
                        rclass: CLASS_IN,
                        ttl: 300,
                        rdata: RData::Nsec(NsecData::new(
                            self.zone.clone(),
                            vec![TYPE_NS, TYPE_RRSIG, TYPE_NSEC],
                        )),
                    };
                    let nsec_sig = sign_rrset_ecdsa_p256(
                        std::slice::from_ref(&nsec),
                        &self.zone,
                        &self.keys.zsk_kp,
                        &self.keys.zsk_pub,
                        self.inception,
                        self.expiration,
                    )
                    .unwrap();
                    authorities.push(nsec);
                    authorities.push(nsec_sig);
                }
                _ => {
                    let ds_rec = Record {
                        name: self.leaf_zone.clone(),
                        rtype: TYPE_DS,
                        rclass: CLASS_IN,
                        ttl: 300,
                        rdata: RData::Ds(self.leaf_ds.clone()),
                    };
                    let ds_sig = sign_rrset_ecdsa_p256(
                        std::slice::from_ref(&ds_rec),
                        &self.zone,
                        &self.keys.zsk_kp,
                        &self.keys.zsk_pub,
                        self.inception,
                        self.expiration,
                    )
                    .unwrap();
                    authorities.push(ds_rec);
                    authorities.push(ds_sig);
                }
            }

            return build_response(req, RCODE_NOERROR, false, Vec::new(), authorities, vec![glue]);
        }

        empty_response(req, RCODE_NXDOMAIN, true)
    }
}

struct LeafState {
    zone: DnsName,
    keys: ZoneKeys,
    mode: LabMode,
    inception: u32,
    expiration: u32,
    now: u32,
    a_records: HashMap<DnsName, Ipv4Addr>,
    nsec_chain: Vec<(DnsName, Record, Record)>,
    nsec3_chain: Vec<(Vec<u8>, Record, Record)>,
    soa: Record,
    soa_sig: Record,
}

impl LeafState {
    fn build(
        zone: DnsName,
        ns_name: DnsName,
        keys: ZoneKeys,
        mode: LabMode,
        inception: u32,
        expiration: u32,
        now: u32,
    ) -> Result<Self, String> {
        let mut a_records = HashMap::new();
        a_records.insert(DnsName::parse_str("alpha.lab.test.")?, Ipv4Addr::new(198, 51, 100, 10));
        a_records.insert(DnsName::parse_str("api.lab.test.")?, Ipv4Addr::new(198, 51, 100, 42));
        a_records.insert(ns_name.clone(), Ipv4Addr::LOCALHOST);
        a_records.insert(
            DnsName::parse_str("secret-staging.lab.test.")?,
            Ipv4Addr::new(198, 51, 100, 99),
        );
        a_records.insert(DnsName::parse_str("www.lab.test.")?, Ipv4Addr::new(198, 51, 100, 20));

        // Canonical sorted list of all names in the zone (apex + hosts)
        let mut names: Vec<DnsName> = a_records.keys().cloned().collect();
        names.push(zone.clone());
        names.sort();

        // Build NSEC chain covering every name in canonical order
        let mut nsec_chain = Vec::new();
        for i in 0..names.len() {
            let owner = names[i].clone();
            let next = names[(i + 1) % names.len()].clone();
            let types = if owner == zone {
                vec![TYPE_NS, TYPE_SOA, TYPE_RRSIG, TYPE_NSEC, TYPE_DNSKEY]
            } else {
                vec![TYPE_A, TYPE_RRSIG, TYPE_NSEC]
            };
            let nsec_rec = Record {
                name: owner.clone(),
                rtype: TYPE_NSEC,
                rclass: CLASS_IN,
                ttl: 300,
                rdata: RData::Nsec(NsecData::new(next, types)),
            };
            let sig = sign_rrset_ecdsa_p256(
                std::slice::from_ref(&nsec_rec),
                &zone,
                &keys.zsk_kp,
                &keys.zsk_pub,
                inception,
                expiration,
            )?;
            nsec_chain.push((owner, nsec_rec, sig));
        }

        // Build NSEC3 chain (SHA-1, iterations=1, salt=DEADBEEF)
        let salt = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut hashed_names: Vec<(Vec<u8>, DnsName)> = names
            .iter()
            .map(|n| Ok((nsec3_hash(n, 1, 1, &salt)?, n.clone())))
            .collect::<Result<Vec<_>, String>>()?;
        hashed_names.sort_by(|a, b| a.0.cmp(&b.0));

        let mut nsec3_chain = Vec::new();
        for i in 0..hashed_names.len() {
            let (ref hash, ref orig_name) = hashed_names[i];
            let next_hash = hashed_names[(i + 1) % hashed_names.len()].0.clone();
            let owner_label = base32hex_encode(hash);
            let owner = zone.prepend_label(owner_label.as_bytes());
            let types = if *orig_name == zone {
                vec![TYPE_NS, TYPE_SOA, TYPE_RRSIG, TYPE_DNSKEY]
            } else {
                vec![TYPE_A, TYPE_RRSIG]
            };
            let nsec3_rec = Record {
                name: owner,
                rtype: TYPE_NSEC3,
                rclass: CLASS_IN,
                ttl: 300,
                rdata: RData::Nsec3(Nsec3Data::new(1, 0, 1, salt.clone(), next_hash, types)),
            };
            let sig = sign_rrset_ecdsa_p256(
                std::slice::from_ref(&nsec3_rec),
                &zone,
                &keys.zsk_kp,
                &keys.zsk_pub,
                inception,
                expiration,
            )?;
            nsec3_chain.push((hash.clone(), nsec3_rec, sig));
        }

        let soa = Record {
            name: zone.clone(),
            rtype: TYPE_SOA,
            rclass: CLASS_IN,
            ttl: 300,
            rdata: RData::Soa {
                mname: ns_name,
                rname: DnsName::parse_str("hostmaster.lab.test.")?,
                serial: 2026112501,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: 300,
            },
        };
        let soa_sig = sign_rrset_ecdsa_p256(
            std::slice::from_ref(&soa),
            &zone,
            &keys.zsk_kp,
            &keys.zsk_pub,
            inception,
            expiration,
        )?;

        Ok(Self {
            zone,
            keys,
            mode,
            inception,
            expiration,
            now,
            a_records,
            nsec_chain,
            nsec3_chain,
            soa,
            soa_sig,
        })
    }

    fn handle_query(&self, req: &Message) -> Message {
        let q = match req.questions.first() {
            Some(q) => q.clone(),
            None => return empty_response(req, RCODE_NOERROR, true),
        };

        if q.name == self.zone && q.qtype == TYPE_DNSKEY {
            let mut answers = self.keys.dnskey_records(&self.zone);
            let sig = sign_rrset_ecdsa_p256(
                &answers,
                &self.zone,
                &self.keys.ksk_kp,
                &self.keys.ksk_pub,
                self.inception,
                self.expiration,
            )
            .unwrap();
            answers.push(sig);
            return build_response(req, RCODE_NOERROR, true, answers, Vec::new(), Vec::new());
        }

        // Direct NSEC query (supports walk-nsec demo!)
        if q.qtype == TYPE_NSEC {
            if let Some((_, nsec, sig)) = self.nsec_chain.iter().find(|(n, _, _)| *n == q.name) {
                return build_response(
                    req,
                    RCODE_NOERROR,
                    true,
                    vec![nsec.clone(), sig.clone()],
                    Vec::new(),
                    Vec::new(),
                );
            }
        }

        // Signed A record answers (with optional tampering modes!)
        if q.qtype == TYPE_A {
            if let Some(&ip) = self.a_records.get(&q.name) {
                let rec = Record {
                    name: q.name.clone(),
                    rtype: TYPE_A,
                    rclass: CLASS_IN,
                    ttl: 300,
                    rdata: RData::A(ip),
                };

                let (inc, exp) = if self.mode == LabMode::ExpiredSig {
                    (self.now.saturating_sub(7200), self.now.saturating_sub(3600))
                } else {
                    (self.inception, self.expiration)
                };

                let sig = sign_rrset_ecdsa_p256(
                    std::slice::from_ref(&rec),
                    &self.zone,
                    &self.keys.zsk_kp,
                    &self.keys.zsk_pub,
                    inc,
                    exp,
                )
                .unwrap();

                let mut final_rec = rec;
                if self.mode == LabMode::TamperIp {
                    // MITM rewrites the IP address in transit without possessing the zone private key
                    final_rec.rdata = RData::A(Ipv4Addr::new(203, 0, 113, 66));
                }

                let answers = if self.mode == LabMode::StripRrsig || self.mode == LabMode::UnsignedZone {
                    vec![final_rec]
                } else {
                    vec![final_rec, sig]
                };

                return build_response(req, RCODE_NOERROR, true, answers, Vec::new(), Vec::new());
            }
        }

        // NXDOMAIN for unknown names under lab.test.
        let mut authorities = vec![self.soa.clone(), self.soa_sig.clone()];
        if self.mode == LabMode::Nsec3 {
            // Return full NSEC3 chain (small 6-record lab zone, guarantees closest encloser + next closer + wildcard)
            for (_, n3, sig) in &self.nsec3_chain {
                authorities.push(n3.clone());
                authorities.push(sig.clone());
            }
        } else {
            for (_, nsec, sig) in &self.nsec_chain {
                authorities.push(nsec.clone());
                authorities.push(sig.clone());
            }
        }
        build_response(req, RCODE_NXDOMAIN, true, Vec::new(), authorities, Vec::new())
    }
}

fn empty_response(req: &Message, rcode: u8, aa: bool) -> Message {
    build_response(req, rcode, aa, Vec::new(), Vec::new(), Vec::new())
}

fn build_response(
    req: &Message,
    rcode: u8,
    aa: bool,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
) -> Message {
    let mut flags = 0x8000u16 | (rcode as u16);
    if aa {
        flags |= 0x0400;
    }
    if req.header.rd() {
        flags |= 0x0100;
    }
    Message {
        header: Header {
            id: req.header.id,
            flags,
            qdcount: req.questions.len() as u16,
            ancount: answers.len() as u16,
            nscount: authorities.len() as u16,
            arcount: additionals.len() as u16,
        },
        questions: req.questions.clone(),
        answers,
        authorities,
        additionals,
    }
}

fn spawn_udp_server<F>(sock: UdpSocket, stop: Arc<AtomicBool>, handler: F) -> thread::JoinHandle<()>
where
    F: Fn(&Message) -> Message + Send + 'static,
{
    let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let resp = handler(&req);
                    let mut wire = resp.encode();
                    if wire.len() > 1232 {
                        // Signal truncation so client exercises real TCP fallback!
                        let mut trunc = resp.clone();
                        trunc.header.flags |= 0x0200;
                        trunc.answers.clear();
                        trunc.authorities.clear();
                        trunc.additionals.clear();
                        wire = trunc.encode();
                    }
                    let _ = sock.send_to(&wire, peer);
                }
            }
        }
    })
}

fn spawn_tcp_server<F>(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    handler: F,
) -> thread::JoinHandle<()>
where
    F: Fn(&Message) -> Message + Send + 'static,
{
    let _ = listener.set_nonblocking(true);
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).is_ok() {
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut body = vec![0u8; len];
                        if stream.read_exact(&mut body).is_ok() {
                            if let Ok(req) = Message::parse(&body) {
                                let wire = handler(&req).encode();
                                let out_len = (wire.len() as u16).to_be_bytes();
                                let _ = stream.write_all(&out_len);
                                let _ = stream.write_all(&wire);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    })
}

/// Runs all local lab scenarios and verifies every expected SECURE / INSECURE / BOGUS outcome.
pub fn run_all_lab_scenarios() -> Result<Vec<(String, SecurityStatus, ValidationResult)>, String> {
    let scenarios = [
        ("valid signed A record", LabMode::Valid, "api.lab.test.", SecurityStatus::Secure),
        ("MITM IP tamper (198.51.100.42 -> 203.0.113.66)", LabMode::TamperIp, "api.lab.test.", SecurityStatus::Bogus),
        ("MITM stripped RRSIG", LabMode::StripRrsig, "api.lab.test.", SecurityStatus::Bogus),
        ("expired RRSIG replay", LabMode::ExpiredSig, "api.lab.test.", SecurityStatus::Bogus),
        ("corrupted parent DS digest", LabMode::BadDs, "api.lab.test.", SecurityStatus::Bogus),
        ("downgrade attack (stripped DS + no NSEC)", LabMode::StripDs, "api.lab.test.", SecurityStatus::Bogus),
        ("legitimate unsigned delegation (NSEC proves no DS)", LabMode::UnsignedZone, "api.lab.test.", SecurityStatus::Insecure),
        ("authenticated NXDOMAIN via NSEC", LabMode::Valid, "ghost.lab.test.", SecurityStatus::Secure),
        ("authenticated NXDOMAIN via NSEC3", LabMode::Nsec3, "ghost.lab.test.", SecurityStatus::Secure),
    ];

    let mut results = Vec::new();
    for (label, mode, target, expected) in scenarios {
        let lab = LocalLab::start(mode)?;
        let resolver = lab.resolver();
        let qname = DnsName::parse_str(target)?;
        let res = resolver.resolve(&qname, TYPE_A);
        lab.stop();
        if res.status != expected {
            return Err(format!(
                "scenario '{label}' expected {:?} but got {:?}: {}",
                expected, res.status, res.summary
            ));
        }
        results.push((label.to_string(), expected, res));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::walk_nsec_zone;
    use crate::transport::DnsTransport;

    #[test]
    fn all_lab_tampering_and_denial_scenarios_pass() {
        let results = run_all_lab_scenarios().expect("all lab scenarios should match expected status");
        assert_eq!(results.len(), 9);
    }

    #[test]
    fn nsec_zone_walk_enumerates_hidden_subdomain_in_lab() {
        let lab = LocalLab::start(LabMode::Valid).unwrap();
        let zone = DnsName::parse_str("lab.test.").unwrap();
        let walked = walk_nsec_zone(&zone, lab.leaf_addr, 20, &DnsTransport::default()).unwrap();
        lab.stop();

        let discovered: Vec<String> = walked.iter().map(|(n, _, _)| n.to_string()).collect();
        assert!(
            discovered.contains(&"secret-staging.lab.test.".to_string()),
            "expected NSEC walk to expose secret-staging.lab.test., got {discovered:?}"
        );
    }
}
