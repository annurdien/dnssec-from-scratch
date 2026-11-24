use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{compute_key_tag, match_dnskey_against_ds, verify_rrset};
use crate::nsec::{verify_nodata, verify_nxdomain};
use crate::rdata::{
    algorithm_name, digest_type_name, hex_decode, hex_upper, type_name, DnskeyData, DsData, RData,
    RrsigData, TYPE_A, TYPE_CNAME, TYPE_DNSKEY, TYPE_DS, TYPE_NS, TYPE_NSEC, TYPE_NSEC3,
    TYPE_RRSIG,
};
use crate::transport::DnsTransport;
use crate::wire::{rcode_name, DnsName, Message, Record, RCODE_NOERROR, RCODE_NXDOMAIN};

/// Active IANA Root Trust Anchors verified from https://data.iana.org/root-anchors/root-anchors.xml
/// KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696).
pub fn iana_root_trust_anchors() -> Vec<DsData> {
    vec![
        DsData {
            key_tag: 20326,
            algorithm: 8,
            digest_type: 2,
            digest: hex_decode("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
                .expect("valid IANA KSK-2017 digest"),
        },
        DsData {
            key_tag: 38696,
            algorithm: 8,
            digest_type: 2,
            digest: hex_decode("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")
                .expect("valid IANA KSK-2024 digest"),
        },
    ]
}

/// Well-known IPv4 addresses of public DNS root servers (IANA root hints).
pub fn default_root_servers() -> Vec<SocketAddr> {
    let ips = [
        Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
        Ipv4Addr::new(170, 247, 170, 2),  // b.root-servers.net
        Ipv4Addr::new(192, 33, 4, 12),    // c.root-servers.net
        Ipv4Addr::new(199, 7, 91, 13),    // d.root-servers.net
        Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
        Ipv4Addr::new(192, 5, 5, 241),    // f.root-servers.net
        Ipv4Addr::new(198, 97, 190, 53),  // h.root-servers.net
        Ipv4Addr::new(192, 36, 148, 17),  // i.root-servers.net
        Ipv4Addr::new(192, 58, 128, 30),  // j.root-servers.net
        Ipv4Addr::new(193, 0, 14, 129),   // k.root-servers.net
        Ipv4Addr::new(199, 7, 83, 42),    // l.root-servers.net
        Ipv4Addr::new(202, 12, 27, 33),   // m.root-servers.net
    ];
    ips.into_iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), 53))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityStatus {
    Secure,
    Insecure,
    Bogus,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub status: SecurityStatus,
    pub qname: DnsName,
    pub qtype: u16,
    pub rcode: u16,
    pub answers: Vec<Record>,
    pub summary: String,
    pub trace: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DnssecResolver {
    pub transport: DnsTransport,
    pub root_servers: Vec<SocketAddr>,
    pub root_anchors: Vec<DsData>,
    /// Optional NS hostname -> SocketAddr overrides (used for local non-port-53 labs).
    pub ns_overrides: HashMap<DnsName, SocketAddr>,
    pub now_override: Option<u32>,
}

impl Default for DnssecResolver {
    fn default() -> Self {
        Self {
            transport: DnsTransport::default(),
            root_servers: default_root_servers(),
            root_anchors: iana_root_trust_anchors(),
            ns_overrides: HashMap::new(),
            now_override: None,
        }
    }
}

impl DnssecResolver {
    fn now_unix(&self) -> u32 {
        self.now_override.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
        })
    }

    pub fn resolve(&self, qname: &DnsName, qtype: u16) -> ValidationResult {
        let mut trace = Vec::new();
        self.resolve_inner(qname, qtype, 0, &mut trace)
    }

    fn resolve_inner(
        &self,
        qname: &DnsName,
        qtype: u16,
        cname_depth: usize,
        trace: &mut Vec<String>,
    ) -> ValidationResult {
        if cname_depth > 8 {
            return ValidationResult {
                status: SecurityStatus::Bogus,
                qname: qname.clone(),
                qtype,
                rcode: 0,
                answers: Vec::new(),
                summary: "CNAME chain exceeded maximum depth (8)".to_string(),
                trace: trace.clone(),
            };
        }

        trace.push(format!(
            "[start] validating {} {} from root trust anchor",
            qname,
            type_name(qtype)
        ));

        // Step 1: Bootstrap root `.` DNSKEYs against the hardcoded trust anchors
        let root_zone = DnsName::root();
        let mut current_zone = root_zone.clone();
        let mut current_servers = self.root_servers.clone();
        let mut current_dnskeys = match self.fetch_and_validate_dnskeys(
            &root_zone,
            &current_servers,
            &self.root_anchors,
            trace,
        ) {
            Ok(keys) => keys,
            Err(err) => {
                return ValidationResult {
                    status: SecurityStatus::Bogus,
                    qname: qname.clone(),
                    qtype,
                    rcode: 0,
                    answers: Vec::new(),
                    summary: format!("root trust anchor validation failed: {err}"),
                    trace: trace.clone(),
                };
            }
        };

        // Special case: user directly queried root DNSKEY
        if *qname == root_zone && qtype == TYPE_DNSKEY {
            let answers = current_dnskeys
                .into_iter()
                .map(|k| Record {
                    name: root_zone.clone(),
                    rtype: TYPE_DNSKEY,
                    rclass: 1,
                    ttl: 0,
                    rdata: RData::Dnskey(k),
                })
                .collect();
            return ValidationResult {
                status: SecurityStatus::Secure,
                qname: qname.clone(),
                qtype,
                rcode: RCODE_NOERROR as u16,
                answers,
                summary: "root DNSKEY RRset verified against trust anchor".to_string(),
                trace: trace.clone(),
            };
        }

        // Step 2: Walk zone cuts down to the authoritative zone for `qname`
        for _step in 0..16 {
            let (resp, used_tcp, server_used) =
                match self.query_any(&current_servers, qname, qtype) {
                    Ok(v) => v,
                    Err(e) => {
                        return ValidationResult {
                            status: SecurityStatus::Bogus,
                            qname: qname.clone(),
                            qtype,
                            rcode: 0,
                            answers: Vec::new(),
                            summary: format!("query to {} failed: {e}", current_zone),
                            trace: trace.clone(),
                        };
                    }
                };

            let proto = if used_tcp { "TCP" } else { "UDP" };
            let rcode = resp.extended_rcode();
            trace.push(format!(
                "[query] {} {} -> {} ({proto}) rcode={} aa={} an={} ns={} ar={}",
                qname,
                type_name(qtype),
                server_used,
                rcode_name(rcode),
                resp.header.aa(),
                resp.answers.len(),
                resp.authorities.len(),
                resp.additionals.len()
            ));

            // Check if this is a referral to a child zone
            if let Some(child_zone) = find_referral_zone(&resp, &current_zone, qname) {
                trace.push(format!(
                    "[referral] {} delegates {} to child nameservers",
                    current_zone, child_zone
                ));

                // Extract DS records from referral authorities, or query current_zone explicitly for DS
                let (ds_rrset, ds_rrsigs, auth_for_denial) =
                    match self.extract_or_fetch_ds(&resp, &current_servers, &child_zone, trace) {
                        Ok(v) => v,
                        Err(e) => {
                            return ValidationResult {
                                status: SecurityStatus::Bogus,
                                qname: qname.clone(),
                                qtype,
                                rcode,
                                answers: Vec::new(),
                                summary: format!("failed fetching DS for {child_zone}: {e}"),
                                trace: trace.clone(),
                            };
                        }
                    };

                if ds_rrset.is_empty() {
                    // No DS found: MUST verify NSEC/NSEC3 proof that DS does not exist!
                    let verified_denial =
                        match self.verify_denial_records(&auth_for_denial, &current_dnskeys, &current_zone) {
                            Ok(v) => v,
                            Err(e) => {
                                return ValidationResult {
                                    status: SecurityStatus::Bogus,
                                    qname: qname.clone(),
                                    qtype,
                                    rcode,
                                    answers: Vec::new(),
                                    summary: format!(
                                        "missing DS for {child_zone} with invalid denial signatures (possible downgrade attack): {e}"
                                    ),
                                    trace: trace.clone(),
                                };
                            }
                        };

                    match verify_nodata(&child_zone, TYPE_DS, &current_zone, &verified_denial) {
                        Ok(proof) => {
                            trace.push(format!("[insecure] {proof}"));
                            // Optionally fetch final unsigned answer so user can inspect it
                            let child_servers =
                                self.extract_referral_servers(&resp, &child_zone, trace);
                            let unsigned_answers = if !child_servers.is_empty() {
                                self.resolve_unsigned_answer(qname, qtype, &child_servers)
                                    .unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            return ValidationResult {
                                status: SecurityStatus::Insecure,
                                qname: qname.clone(),
                                qtype,
                                rcode: RCODE_NOERROR as u16,
                                answers: unsigned_answers,
                                summary: format!(
                                    "provably insecure delegation at {child_zone} ({proof})"
                                ),
                                trace: trace.clone(),
                            };
                        }
                        Err(e) => {
                            return ValidationResult {
                                status: SecurityStatus::Bogus,
                                qname: qname.clone(),
                                qtype,
                                rcode,
                                answers: Vec::new(),
                                summary: format!(
                                    "missing DS for {child_zone} without valid NSEC/NSEC3 proof (possible DS stripping): {e}"
                                ),
                                trace: trace.clone(),
                            };
                        }
                    }
                }

                // Verify RRSIG(DS) using parent's validated DNSKEYs
                let ds_sig = match verify_rrset(
                    &ds_rrset,
                    &ds_rrsigs,
                    &current_dnskeys,
                    &current_zone,
                    self.now_unix(),
                ) {
                    Ok(sig) => sig,
                    Err(e) => {
                        return ValidationResult {
                            status: SecurityStatus::Bogus,
                            qname: qname.clone(),
                            qtype,
                            rcode,
                            answers: Vec::new(),
                            summary: format!("DS RRSIG verification failed for {child_zone}: {e}"),
                            trace: trace.clone(),
                        };
                    }
                };

                let ds_values: Vec<DsData> = ds_rrset
                    .iter()
                    .filter_map(|r| match &r.rdata {
                        RData::Ds(d) => Some(d.clone()),
                        _ => None,
                    })
                    .collect();

                for ds in &ds_values {
                    trace.push(format!(
                        "[ds] verified {} DS tag={} alg={}({}) {}={} (signed by {} keytag={})",
                        child_zone,
                        ds.key_tag,
                        ds.algorithm,
                        algorithm_name(ds.algorithm),
                        digest_type_name(ds.digest_type),
                        &hex_upper(&ds.digest)[..16.min(ds.digest.len() * 2)],
                        ds_sig.signer_name,
                        ds_sig.key_tag
                    ));
                }

                // If user explicitly queried DS for this exact child zone, we are done!
                if *qname == child_zone && qtype == TYPE_DS {
                    return ValidationResult {
                        status: SecurityStatus::Secure,
                        qname: qname.clone(),
                        qtype,
                        rcode: RCODE_NOERROR as u16,
                        answers: ds_rrset,
                        summary: format!(
                            "DS RRset for {child_zone} verified by {} key tag {}",
                            ds_sig.signer_name, ds_sig.key_tag
                        ),
                        trace: trace.clone(),
                    };
                }

                // Resolve child nameserver addresses (glue or recursive NS lookup)
                let child_servers = self.extract_referral_servers(&resp, &child_zone, trace);
                if child_servers.is_empty() {
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: format!("could not resolve any IPv4 nameserver for {child_zone}"),
                        trace: trace.clone(),
                    };
                }

                // Fetch and validate child zone DNSKEYs against the parent's validated DS records
                let child_keys = match self.fetch_and_validate_dnskeys(
                    &child_zone,
                    &child_servers,
                    &ds_values,
                    trace,
                ) {
                    Ok(keys) => keys,
                    Err(e) => {
                        return ValidationResult {
                            status: SecurityStatus::Bogus,
                            qname: qname.clone(),
                            qtype,
                            rcode,
                            answers: Vec::new(),
                            summary: format!("DNSKEY validation failed at {child_zone}: {e}"),
                            trace: trace.clone(),
                        };
                    }
                };

                current_zone = child_zone;
                current_servers = child_servers;
                current_dnskeys = child_keys;

                if *qname == current_zone && qtype == TYPE_DNSKEY {
                    let answers = current_dnskeys
                        .into_iter()
                        .map(|k| Record {
                            name: current_zone.clone(),
                            rtype: TYPE_DNSKEY,
                            rclass: 1,
                            ttl: 0,
                            rdata: RData::Dnskey(k),
                        })
                        .collect();
                    return ValidationResult {
                        status: SecurityStatus::Secure,
                        qname: qname.clone(),
                        qtype,
                        rcode: RCODE_NOERROR as u16,
                        answers,
                        summary: format!(
                            "DNSKEY RRset for {current_zone} verified against parent DS"
                        ),
                        trace: trace.clone(),
                    };
                }
                continue;
            }

            // Co-hosted child zone check: same nameserver answered directly with a deeper signer_name
            if let Some(deeper_zone) = find_deeper_signer(&resp, &current_zone, qname) {
                trace.push(format!(
                    "[subzone] co-hosted zone cut detected: {} -> {}",
                    current_zone, deeper_zone
                ));
                let (ds_rrset, ds_rrsigs, auth_for_denial) =
                    match self.fetch_ds_explicit(&current_servers, &deeper_zone, trace) {
                        Ok(v) => v,
                        Err(e) => {
                            return ValidationResult {
                                status: SecurityStatus::Bogus,
                                qname: qname.clone(),
                                qtype,
                                rcode,
                                answers: Vec::new(),
                                summary: format!("failed fetching DS for subzone {deeper_zone}: {e}"),
                                trace: trace.clone(),
                            };
                        }
                    };
                if ds_rrset.is_empty() {
                    let verified_denial =
                        match self.verify_denial_records(&auth_for_denial, &current_dnskeys, &current_zone) {
                            Ok(v) => v,
                            Err(e) => {
                                return ValidationResult {
                                    status: SecurityStatus::Bogus,
                                    qname: qname.clone(),
                                    qtype,
                                    rcode,
                                    answers: Vec::new(),
                                    summary: format!("subzone {deeper_zone} missing DS with invalid denial: {e}"),
                                    trace: trace.clone(),
                                };
                            }
                        };
                    if let Ok(proof) = verify_nodata(&deeper_zone, TYPE_DS, &current_zone, &verified_denial) {
                        trace.push(format!("[insecure] {proof}"));
                        return ValidationResult {
                            status: SecurityStatus::Insecure,
                            qname: qname.clone(),
                            qtype,
                            rcode,
                            answers: resp.answers,
                            summary: format!("provably insecure subzone {deeper_zone} ({proof})"),
                            trace: trace.clone(),
                        };
                    }
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: format!("subzone {deeper_zone} missing DS without denial proof"),
                        trace: trace.clone(),
                    };
                }
                if let Err(e) = verify_rrset(
                    &ds_rrset,
                    &ds_rrsigs,
                    &current_dnskeys,
                    &current_zone,
                    self.now_unix(),
                ) {
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: format!("subzone DS RRSIG failed for {deeper_zone}: {e}"),
                        trace: trace.clone(),
                    };
                }
                let ds_values: Vec<DsData> = ds_rrset
                    .iter()
                    .filter_map(|r| match &r.rdata {
                        RData::Ds(d) => Some(d.clone()),
                        _ => None,
                    })
                    .collect();
                let child_keys = match self.fetch_and_validate_dnskeys(
                    &deeper_zone,
                    &current_servers,
                    &ds_values,
                    trace,
                ) {
                    Ok(keys) => keys,
                    Err(e) => {
                        return ValidationResult {
                            status: SecurityStatus::Bogus,
                            qname: qname.clone(),
                            qtype,
                            rcode,
                            answers: Vec::new(),
                            summary: format!("subzone DNSKEY validation failed for {deeper_zone}: {e}"),
                            trace: trace.clone(),
                        };
                    }
                };
                current_zone = deeper_zone;
                current_dnskeys = child_keys;
                // Re-process this exact response under the newly validated child zone!
            }

            // Step 3: We reached the authoritative zone! Validate final answer / CNAME / NXDOMAIN / NODATA
            return self.validate_authoritative_response(
                &resp,
                qname,
                qtype,
                &current_zone,
                &current_dnskeys,
                cname_depth,
                trace,
            );
        }

        ValidationResult {
            status: SecurityStatus::Bogus,
            qname: qname.clone(),
            qtype,
            rcode: 0,
            answers: Vec::new(),
            summary: "exceeded maximum delegation depth (16)".to_string(),
            trace: trace.clone(),
        }
    }

    fn validate_authoritative_response(
        &self,
        resp: &Message,
        qname: &DnsName,
        qtype: u16,
        zone: &DnsName,
        dnskeys: &[DnskeyData],
        cname_depth: usize,
        trace: &mut Vec<String>,
    ) -> ValidationResult {
        let rcode = resp.extended_rcode();
        let now = self.now_unix();

        // Collect answers matching (qname, qtype)
        let matching_answers: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| r.name == *qname && r.rtype == qtype)
            .cloned()
            .collect();

        if !matching_answers.is_empty() {
            let rrsigs = collect_rrsigs(&resp.answers, qname);
            match verify_rrset(&matching_answers, &rrsigs, dnskeys, zone, now) {
                Ok(sig) => {
                    trace.push(format!(
                        "[verify] {} {} RRSIG VALID (signer={}, keytag={}, alg={}, valid={}..{})",
                        qname,
                        type_name(qtype),
                        sig.signer_name,
                        sig.key_tag,
                        algorithm_name(sig.algorithm),
                        sig.inception,
                        sig.expiration
                    ));
                    return ValidationResult {
                        status: SecurityStatus::Secure,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: matching_answers,
                        summary: format!(
                            "verified {} {} via {} (key tag {}, {})",
                            qname,
                            type_name(qtype),
                            sig.signer_name,
                            sig.key_tag,
                            algorithm_name(sig.algorithm)
                        ),
                        trace: trace.clone(),
                    };
                }
                Err(e) => {
                    trace.push(format!("[bogus] {e}"));
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: matching_answers,
                        summary: e,
                        trace: trace.clone(),
                    };
                }
            }
        }

        // Check for CNAME at qname
        let cname_records: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| r.name == *qname && r.rtype == TYPE_CNAME)
            .cloned()
            .collect();
        if !cname_records.is_empty() && qtype != TYPE_CNAME {
            let rrsigs = collect_rrsigs(&resp.answers, qname);
            match verify_rrset(&cname_records, &rrsigs, dnskeys, zone, now) {
                Ok(sig) => {
                    let target = match &cname_records[0].rdata {
                        RData::Cname(t) => t.clone(),
                        _ => unreachable!(),
                    };
                    trace.push(format!(
                        "[cname] {} -> {} verified by {} keytag={}; following target",
                        qname, target, sig.signer_name, sig.key_tag
                    ));
                    let mut target_res = self.resolve_inner(&target, qtype, cname_depth + 1, trace);
                    let mut combined = cname_records;
                    combined.extend(target_res.answers);
                    target_res.answers = combined;
                    return target_res;
                }
                Err(e) => {
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: cname_records,
                        summary: format!("CNAME RRSIG verification failed: {e}"),
                        trace: trace.clone(),
                    };
                }
            }
        }

        // NXDOMAIN proof
        if rcode == RCODE_NXDOMAIN as u16 {
            let verified_denial = match self.verify_denial_records(&resp.authorities, dnskeys, zone) {
                Ok(v) => v,
                Err(e) => {
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: format!("NXDOMAIN NSEC/NSEC3 RRSIG failed: {e}"),
                        trace: trace.clone(),
                    };
                }
            };
            match verify_nxdomain(qname, zone, &verified_denial) {
                Ok(proof) => {
                    trace.push(format!("[nxdomain] {proof}"));
                    return ValidationResult {
                        status: SecurityStatus::Secure,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: proof,
                        trace: trace.clone(),
                    };
                }
                Err(e) => {
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: format!("NXDOMAIN proof rejected: {e}"),
                        trace: trace.clone(),
                    };
                }
            }
        }

        // NODATA proof (NOERROR with no matching answers)
        if rcode == RCODE_NOERROR as u16 {
            let verified_denial = match self.verify_denial_records(&resp.authorities, dnskeys, zone) {
                Ok(v) => v,
                Err(e) => {
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: format!("NODATA NSEC/NSEC3 RRSIG failed: {e}"),
                        trace: trace.clone(),
                    };
                }
            };
            match verify_nodata(qname, qtype, zone, &verified_denial) {
                Ok(proof) => {
                    trace.push(format!("[nodata] {proof}"));
                    return ValidationResult {
                        status: SecurityStatus::Secure,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: proof,
                        trace: trace.clone(),
                    };
                }
                Err(e) => {
                    return ValidationResult {
                        status: SecurityStatus::Bogus,
                        qname: qname.clone(),
                        qtype,
                        rcode,
                        answers: Vec::new(),
                        summary: format!("NODATA proof rejected: {e}"),
                        trace: trace.clone(),
                    };
                }
            }
        }

        ValidationResult {
            status: SecurityStatus::Bogus,
            qname: qname.clone(),
            qtype,
            rcode,
            answers: Vec::new(),
            summary: format!("authoritative server returned unexpected rcode {}", rcode_name(rcode)),
            trace: trace.clone(),
        }
    }

    /// Fetches `zone DNSKEY`, matches at least one key against `expected_ds`, and verifies `RRSIG(DNSKEY)`.
    fn fetch_and_validate_dnskeys(
        &self,
        zone: &DnsName,
        servers: &[SocketAddr],
        expected_ds: &[DsData],
        trace: &mut Vec<String>,
    ) -> Result<Vec<DnskeyData>, String> {
        let (resp, used_tcp, server_used) = self.query_any(servers, zone, TYPE_DNSKEY)?;
        let proto = if used_tcp { "TCP" } else { "UDP" };
        let key_records: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| r.name == *zone && r.rtype == TYPE_DNSKEY)
            .cloned()
            .collect();

        if key_records.is_empty() {
            return Err(format!(
                "no DNSKEY records returned for {zone} from {server_used} ({proto})"
            ));
        }

        let dnskeys: Vec<DnskeyData> = key_records
            .iter()
            .filter_map(|r| match &r.rdata {
                RData::Dnskey(k) => Some(k.clone()),
                _ => None,
            })
            .collect();

        let matched = match_dnskey_against_ds(zone, &dnskeys, expected_ds);
        if matched.is_empty() {
            let got_tags: Vec<String> = dnskeys
                .iter()
                .map(|k| format!("{}(flags={})", compute_key_tag(k), k.flags))
                .collect();
            let want_tags: Vec<String> = expected_ds
                .iter()
                .map(|d| format!("{}(alg={},dtype={})", d.key_tag, d.algorithm, d.digest_type))
                .collect();
            return Err(format!(
                "no DNSKEY at {zone} matched DS digest (got tags [{}], expected DS [{}])",
                got_tags.join(", "),
                want_tags.join(", ")
            ));
        }

        let trusted_ksks: Vec<DnskeyData> = matched.iter().map(|(k, _)| (*k).clone()).collect();
        let rrsigs = collect_rrsigs(&resp.answers, zone);

        let verified = verify_rrset(&key_records, &rrsigs, &trusted_ksks, zone, self.now_unix())?;
        let sep_count = dnskeys.iter().filter(|k| k.is_sep()).count();
        trace.push(format!(
            "[dnskey] {} verified {} keys ({} KSK/SEP, {} ZSK) from {} ({proto}): KSK tag={} matched DS and signed DNSKEY RRset",
            zone,
            dnskeys.len(),
            sep_count,
            dnskeys.len().saturating_sub(sep_count),
            server_used,
            verified.key_tag
        ));

        Ok(dnskeys)
    }

    fn extract_or_fetch_ds(
        &self,
        referral: &Message,
        parent_servers: &[SocketAddr],
        child_zone: &DnsName,
        trace: &mut Vec<String>,
    ) -> Result<(Vec<Record>, Vec<RrsigData>, Vec<Record>), String> {
        let ds_rrset: Vec<Record> = referral
            .authorities
            .iter()
            .filter(|r| r.name == *child_zone && r.rtype == TYPE_DS)
            .cloned()
            .collect();
        if !ds_rrset.is_empty() {
            let ds_sigs = collect_rrsigs(&referral.authorities, child_zone);
            return Ok((ds_rrset, ds_sigs, referral.authorities.clone()));
        }

        // Check if referral already contains NSEC/NSEC3 records for DS non-existence
        let has_denial = referral
            .authorities
            .iter()
            .any(|r| r.rtype == TYPE_NSEC || r.rtype == TYPE_NSEC3);
        if has_denial {
            return Ok((Vec::new(), Vec::new(), referral.authorities.clone()));
        }

        self.fetch_ds_explicit(parent_servers, child_zone, trace)
    }

    fn fetch_ds_explicit(
        &self,
        parent_servers: &[SocketAddr],
        child_zone: &DnsName,
        trace: &mut Vec<String>,
    ) -> Result<(Vec<Record>, Vec<RrsigData>, Vec<Record>), String> {
        let (resp, used_tcp, server_used) = self.query_any(parent_servers, child_zone, TYPE_DS)?;
        let proto = if used_tcp { "TCP" } else { "UDP" };
        trace.push(format!(
            "[query] explicit {} DS -> {} ({proto}) an={} ns={}",
            child_zone,
            server_used,
            resp.answers.len(),
            resp.authorities.len()
        ));
        let ds_rrset: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| r.name == *child_zone && r.rtype == TYPE_DS)
            .cloned()
            .collect();
        let ds_sigs = collect_rrsigs(&resp.answers, child_zone);
        Ok((ds_rrset, ds_sigs, resp.authorities))
    }

    /// Cryptographically verifies every NSEC and NSEC3 RRset present in `authorities`.
    fn verify_denial_records(
        &self,
        authorities: &[Record],
        dnskeys: &[DnskeyData],
        zone: &DnsName,
    ) -> Result<Vec<Record>, String> {
        let now = self.now_unix();
        let mut grouped: HashMap<(DnsName, u16), Vec<Record>> = HashMap::new();
        for r in authorities {
            if r.rtype == TYPE_NSEC || r.rtype == TYPE_NSEC3 {
                grouped
                    .entry((r.name.clone(), r.rtype))
                    .or_default()
                    .push(r.clone());
            }
        }

        if grouped.is_empty() {
            return Err("no NSEC or NSEC3 records present in authority section".to_string());
        }

        let mut verified = Vec::new();
        for ((owner, _rtype), rrset) in grouped {
            let sigs = collect_rrsigs(authorities, &owner);
            verify_rrset(&rrset, &sigs, dnskeys, zone, now)?;
            verified.extend(rrset);
        }
        Ok(verified)
    }

    fn extract_referral_servers(
        &self,
        resp: &Message,
        child_zone: &DnsName,
        trace: &mut Vec<String>,
    ) -> Vec<SocketAddr> {
        let mut ns_names: Vec<DnsName> = resp
            .authorities
            .iter()
            .filter(|r| r.name == *child_zone && r.rtype == TYPE_NS)
            .filter_map(|r| match &r.rdata {
                RData::Ns(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        ns_names.sort();
        ns_names.dedup();

        let mut addrs = Vec::new();
        // 1. Check local lab overrides first
        for ns in &ns_names {
            if let Some(&addr) = self.ns_overrides.get(ns) {
                addrs.push(addr);
            }
        }
        if !addrs.is_empty() {
            return addrs;
        }

        // 2. Check glue A records in additionals
        for ns in &ns_names {
            for rr in &resp.additionals {
                if rr.name == *ns {
                    if let RData::A(ip) = rr.rdata {
                        addrs.push(SocketAddr::new(IpAddr::V4(ip), 53));
                    }
                }
            }
        }
        if !addrs.is_empty() {
            return addrs;
        }

        // 3. Glueless referral: resolve up to 2 NS hostnames iteratively to get IPv4 addresses
        for ns in ns_names.iter().take(2) {
            if let Ok(ips) = self.resolve_ns_ipv4(ns, 0) {
                for ip in ips {
                    trace.push(format!("[glue] resolved glueless NS {ns} -> {ip}"));
                    addrs.push(SocketAddr::new(IpAddr::V4(ip), 53));
                }
                if !addrs.is_empty() {
                    break;
                }
            }
        }
        addrs
    }

    /// Lightweight iterative IPv4 resolver used strictly to locate glueless NS endpoints.
    fn resolve_ns_ipv4(&self, ns_name: &DnsName, depth: usize) -> Result<Vec<Ipv4Addr>, String> {
        if depth > 4 {
            return Err("glueless NS resolution depth exceeded".to_string());
        }
        let mut servers = self.root_servers.clone();
        let mut current_zone = DnsName::root();

        for _ in 0..10 {
            let (resp, _, _) = self.query_any(&servers, ns_name, TYPE_A)?;
            let ips: Vec<Ipv4Addr> = resp
                .answers
                .iter()
                .filter(|r| r.name == *ns_name && r.rtype == TYPE_A)
                .filter_map(|r| match r.rdata {
                    RData::A(ip) => Some(ip),
                    _ => None,
                })
                .collect();
            if !ips.is_empty() {
                return Ok(ips);
            }

            if let Some(child_zone) = find_referral_zone(&resp, &current_zone, ns_name) {
                let mut next_servers = Vec::new();
                let mut child_ns = Vec::new();
                for rr in &resp.authorities {
                    if rr.name == child_zone {
                        if let RData::Ns(n) = &rr.rdata {
                            child_ns.push(n.clone());
                        }
                    }
                }
                for ns in &child_ns {
                    for rr in &resp.additionals {
                        if rr.name == *ns {
                            if let RData::A(ip) = rr.rdata {
                                next_servers.push(SocketAddr::new(IpAddr::V4(ip), 53));
                            }
                        }
                    }
                }
                if next_servers.is_empty() {
                    for ns in child_ns.iter().take(1) {
                        if let Ok(found) = self.resolve_ns_ipv4(ns, depth + 1) {
                            next_servers.extend(
                                found
                                    .into_iter()
                                    .map(|ip| SocketAddr::new(IpAddr::V4(ip), 53)),
                            );
                        }
                    }
                }
                if next_servers.is_empty() {
                    return Err(format!("no glue for {child_zone}"));
                }
                current_zone = child_zone;
                servers = next_servers;
            } else {
                break;
            }
        }
        Err(format!("could not resolve A record for NS {ns_name}"))
    }

    fn resolve_unsigned_answer(
        &self,
        qname: &DnsName,
        qtype: u16,
        start_servers: &[SocketAddr],
    ) -> Result<Vec<Record>, String> {
        let mut servers = start_servers.to_vec();
        let mut zone = DnsName::root();
        for _ in 0..8 {
            let (resp, _, _) = self.query_any(&servers, qname, qtype)?;
            if !resp.answers.is_empty() {
                return Ok(resp
                    .answers
                    .into_iter()
                    .filter(|r| r.rtype != TYPE_RRSIG)
                    .collect());
            }
            if let Some(child) = find_referral_zone(&resp, &zone, qname) {
                let mut dummy_trace = Vec::new();
                let next = self.extract_referral_servers(&resp, &child, &mut dummy_trace);
                if next.is_empty() {
                    break;
                }
                zone = child;
                servers = next;
            } else {
                break;
            }
        }
        Ok(Vec::new())
    }

    fn query_any(
        &self,
        servers: &[SocketAddr],
        name: &DnsName,
        qtype: u16,
    ) -> Result<(Message, bool, SocketAddr), String> {
        let mut last_err = "no nameservers available".to_string();
        for &server in servers.iter().take(4) {
            match self.transport.query(server, name, qtype, false) {
                Ok((msg, used_tcp)) => return Ok((msg, used_tcp, server)),
                Err(e) => last_err = format!("{server}: {e}"),
            }
        }
        Err(last_err)
    }
}

fn collect_rrsigs(records: &[Record], owner: &DnsName) -> Vec<RrsigData> {
    records
        .iter()
        .filter(|r| r.name == *owner && r.rtype == TYPE_RRSIG)
        .filter_map(|r| match &r.rdata {
            RData::Rrsig(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn find_referral_zone(resp: &Message, current_zone: &DnsName, qname: &DnsName) -> Option<DnsName> {
    if !resp.answers.is_empty() {
        return None;
    }
    let mut best: Option<DnsName> = None;
    for rr in &resp.authorities {
        if rr.rtype == TYPE_NS
            && rr.name != *current_zone
            && rr.name.is_subdomain_of(current_zone)
            && qname.is_subdomain_of(&rr.name)
        {
            match &best {
                None => best = Some(rr.name.clone()),
                Some(b) if rr.name.label_count() > b.label_count() => best = Some(rr.name.clone()),
                _ => {}
            }
        }
    }
    best
}

fn find_deeper_signer(resp: &Message, current_zone: &DnsName, qname: &DnsName) -> Option<DnsName> {
    let mut best: Option<DnsName> = None;
    for rr in resp.answers.iter().chain(resp.authorities.iter()) {
        if let RData::Rrsig(sig) = &rr.rdata {
            if sig.signer_name != *current_zone
                && sig.signer_name.is_subdomain_of(current_zone)
                && qname.is_subdomain_of(&sig.signer_name)
            {
                match &best {
                    None => best = Some(sig.signer_name.clone()),
                    Some(b) if sig.signer_name.label_count() < b.label_count() => {
                        best = Some(sig.signer_name.clone())
                    }
                    _ => {}
                }
            }
        }
    }
    best
}

/// Demonstrates NSEC zone walking by following `next_domain_name` links starting from `zone`.
pub fn walk_nsec_zone(
    zone: &DnsName,
    server: SocketAddr,
    max_steps: usize,
    transport: &DnsTransport,
) -> Result<Vec<(DnsName, DnsName, Vec<u16>)>, String> {
    let mut current = zone.clone();
    let mut visited = Vec::new();

    for _ in 0..max_steps {
        let (resp, _) = transport.query(server, &current, TYPE_NSEC, false)?;
        let nsec_rec = resp
            .answers
            .iter()
            .chain(resp.authorities.iter())
            .find_map(|r| match &r.rdata {
                RData::Nsec(n) if r.name == current => Some(n.clone()),
                _ => None,
            })
            .or_else(|| {
                resp.answers
                    .iter()
                    .chain(resp.authorities.iter())
                    .find_map(|r| match &r.rdata {
                        RData::Nsec(n) => Some(n.clone()),
                        _ => None,
                    })
            });

        let Some(nsec) = nsec_rec else {
            return Err(format!(
                "no NSEC record returned for {current} from {server} (zone may use NSEC3 or be unsigned)"
            ));
        };

        let next = nsec.next_domain_name.clone();
        visited.push((current.clone(), next.clone(), nsec.types));
        if next == *zone || visited.iter().any(|(seen, _, _)| *seen == next) {
            break;
        }
        current = next;
    }

    Ok(visited)
}
