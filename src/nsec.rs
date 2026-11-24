use std::cmp::Ordering;

use ring::digest;

use crate::rdata::{Nsec3Data, NsecData, RData, TYPE_CNAME, TYPE_DNAME, TYPE_DS, TYPE_NS, TYPE_SOA};
use crate::wire::{DnsName, Record};

const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
pub const MAX_NSEC3_ITERATIONS: u16 = 500;

/// Encodes bytes using RFC 4648 Section 7 Extended Hex Base32 (no padding), used by NSEC3 labels.
pub fn base32hex_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input {
        buffer = (buffer << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(BASE32HEX_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(BASE32HEX_ALPHABET[idx] as char);
    }
    out
}

/// Decodes RFC 4648 Section 7 Extended Hex Base32 (case-insensitive, no padding).
pub fn base32hex_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((input.len() * 5) / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input {
        let val = match b.to_ascii_uppercase() {
            b'0'..=b'9' => (b - b'0') as u32,
            b'A'..=b'V' => (b.to_ascii_uppercase() - b'A' + 10) as u32,
            other => return Err(format!("invalid base32hex character: 0x{other:02x}")),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Computes RFC 5155 Section 5 iterative SHA-1 NSEC3 hash:
/// IH(salt, x, 0) = SHA1(x || salt)
/// IH(salt, x, k) = SHA1(IH(salt, x, k-1) || salt)
/// Total SHA-1 evaluations = `iterations + 1`.
pub fn nsec3_hash(
    name: &DnsName,
    hash_alg: u8,
    iterations: u16,
    salt: &[u8],
) -> Result<Vec<u8>, String> {
    if hash_alg != 1 {
        return Err(format!("unsupported NSEC3 hash algorithm: {hash_alg}"));
    }
    if iterations > MAX_NSEC3_ITERATIONS {
        return Err(format!(
            "NSEC3 iteration count {iterations} exceeds safety cap ({MAX_NSEC3_ITERATIONS})"
        ));
    }

    let wire = name.to_canonical_wire();
    let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(&wire);
    ctx.update(salt);
    let mut current = ctx.finish().as_ref().to_vec();

    for _ in 0..iterations {
        let mut iter_ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        iter_ctx.update(&current);
        iter_ctx.update(salt);
        current = iter_ctx.finish().as_ref().to_vec();
    }
    Ok(current)
}

/// Returns true if an NSEC record `(owner, next)` strictly covers `target` in canonical order within `zone`.
pub fn nsec_covers(owner: &DnsName, next: &DnsName, target: &DnsName, zone: &DnsName) -> bool {
    if !target.is_subdomain_of(zone) {
        return false;
    }
    match owner.canonical_cmp(next) {
        Ordering::Less => {
            target.canonical_cmp(owner) == Ordering::Greater
                && target.canonical_cmp(next) == Ordering::Less
        }
        Ordering::Greater => {
            // Last NSEC in the zone wraps around back to the zone apex
            target.canonical_cmp(owner) == Ordering::Greater
                || target.canonical_cmp(next) == Ordering::Less
        }
        Ordering::Equal => {
            // Single-name zone: apex NSEC points to itself and covers every strict subdomain
            target != owner
        }
    }
}

/// Returns true if an NSEC3 hash interval `(owner_hash, next_hash)` strictly covers `target_hash`.
pub fn nsec3_covers(owner_hash: &[u8], next_hash: &[u8], target_hash: &[u8]) -> bool {
    if owner_hash.len() != next_hash.len() || owner_hash.len() != target_hash.len() {
        return false;
    }
    match owner_hash.cmp(next_hash) {
        Ordering::Less => target_hash > owner_hash && target_hash < next_hash,
        Ordering::Greater => target_hash > owner_hash || target_hash < next_hash,
        Ordering::Equal => target_hash != owner_hash,
    }
}

fn longest_common_suffix(a: &DnsName, b: &DnsName) -> DnsName {
    let mut common = Vec::new();
    for (la, lb) in a.labels().iter().rev().zip(b.labels().iter().rev()) {
        if la.eq_ignore_ascii_case(lb) {
            common.push(la.clone());
        } else {
            break;
        }
    }
    common.reverse();
    DnsName::from_labels(common)
}

fn extract_nsecs(records: &[Record]) -> Vec<(&DnsName, &NsecData)> {
    records
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::Nsec(n) => Some((&r.name, n)),
            _ => None,
        })
        .collect()
}

fn extract_nsec3s<'a>(records: &'a [Record], zone: &DnsName) -> Vec<(Vec<u8>, &'a Nsec3Data)> {
    let mut out = Vec::new();
    for r in records {
        if let RData::Nsec3(n3) = &r.rdata {
            if r.name.label_count() == zone.label_count() + 1 && r.name.is_subdomain_of(zone) {
                if let Some(first) = r.name.labels().first() {
                    if let Ok(owner_hash) = base32hex_decode(first) {
                        out.push((owner_hash, n3));
                    }
                }
            }
        }
    }
    out
}

/// Verifies an authenticated NXDOMAIN proof using already RRSIG-verified NSEC or NSEC3 records.
pub fn verify_nxdomain(
    qname: &DnsName,
    zone: &DnsName,
    verified_records: &[Record],
) -> Result<String, String> {
    let nsecs = extract_nsecs(verified_records);
    if !nsecs.is_empty() {
        return verify_nxdomain_nsec(qname, zone, &nsecs);
    }
    let nsec3s = extract_nsec3s(verified_records, zone);
    if !nsec3s.is_empty() {
        return verify_nxdomain_nsec3(qname, zone, &nsec3s);
    }
    Err(format!(
        "NXDOMAIN for {qname} lacks verified NSEC or NSEC3 records"
    ))
}

fn verify_nxdomain_nsec(
    qname: &DnsName,
    zone: &DnsName,
    nsecs: &[(&DnsName, &NsecData)],
) -> Result<String, String> {
    let Some((cov_owner, cov_nsec)) = nsecs
        .iter()
        .copied()
        .find(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain_name, qname, zone))
    else {
        return Err(format!("no verified NSEC covers {qname}"));
    };

    // Determine closest encloser as longest common suffix with covering NSEC endpoints (bounded by zone)
    let suffix_owner = longest_common_suffix(qname, cov_owner);
    let suffix_next = longest_common_suffix(qname, &cov_nsec.next_domain_name);
    let mut ce = if suffix_owner.label_count() >= suffix_next.label_count() {
        suffix_owner
    } else {
        suffix_next
    };
    if ce.label_count() < zone.label_count() {
        ce = zone.clone();
    }

    let wildcard = ce.prepend_label(b"*");
    let wildcard_covered = wildcard == *qname
        || nsecs
            .iter()
            .any(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain_name, &wildcard, zone));

    if !wildcard_covered {
        return Err(format!(
            "NSEC covers {qname} ({cov_owner} -> {}), but no NSEC covers wildcard {wildcard}",
            cov_nsec.next_domain_name
        ));
    }

    Ok(format!(
        "NSEC proves {qname} does not exist (covered by {cov_owner} -> {}, wildcard {wildcard} absent)",
        cov_nsec.next_domain_name
    ))
}

fn verify_nxdomain_nsec3(
    qname: &DnsName,
    zone: &DnsName,
    nsec3s: &[(Vec<u8>, &Nsec3Data)],
) -> Result<String, String> {
    let params = nsec3s[0].1;

    // 1. Find closest encloser (exact hash match among strict ancestors of qname up to zone)
    let mut candidate = qname.parent();
    let mut closest_encloser: Option<(DnsName, DnsName)> = None;
    let mut child = qname.clone();

    while let Some(anc) = candidate {
        if !anc.is_subdomain_of(zone) {
            break;
        }
        let h = nsec3_hash(&anc, params.hash_algorithm, params.iterations, &params.salt)?;
        if let Some((_, matched_n3)) = nsec3s.iter().find(|(owner_h, _)| *owner_h == h) {
            // Closest encloser must not be a delegation cut (NS without SOA) or DNAME
            let is_delegation = matched_n3.has_type(TYPE_NS) && !matched_n3.has_type(TYPE_SOA);
            if !is_delegation && !matched_n3.has_type(TYPE_DNAME) {
                closest_encloser = Some((anc.clone(), child));
                break;
            }
        }
        child = anc.clone();
        candidate = anc.parent();
    }

    let Some((ce, next_closer)) = closest_encloser else {
        return Err(format!(
            "NSEC3 NXDOMAIN proof failed: no closest encloser matched for {qname} in {zone}"
        ));
    };

    // 2. Verify next closer name is covered by an NSEC3 record
    let nc_hash = nsec3_hash(&next_closer, params.hash_algorithm, params.iterations, &params.salt)?;
    let nc_cover = nsec3s
        .iter()
        .find(|(owner_h, n3)| nsec3_covers(owner_h, &n3.next_hashed_owner, &nc_hash));
    let Some((nc_owner_h, nc_n3)) = nc_cover else {
        return Err(format!(
            "NSEC3 NXDOMAIN proof failed: next closer {next_closer} (hash {}) not covered",
            base32hex_encode(&nc_hash)
        ));
    };

    // 3. Verify wildcard at closest encloser (`*.<ce>`) is covered
    let wildcard = ce.prepend_label(b"*");
    let wc_hash = nsec3_hash(&wildcard, params.hash_algorithm, params.iterations, &params.salt)?;
    let wc_covered = nsec3s
        .iter()
        .any(|(owner_h, n3)| nsec3_covers(owner_h, &n3.next_hashed_owner, &wc_hash));
    if !wc_covered {
        return Err(format!(
            "NSEC3 NXDOMAIN proof failed: wildcard {wildcard} (hash {}) not covered",
            base32hex_encode(&wc_hash)
        ));
    }

    Ok(format!(
        "NSEC3 proves {qname} does not exist (closest encloser={ce}, next closer={next_closer} covered by {}..{}, wildcard {wildcard} covered)",
        base32hex_encode(nc_owner_h),
        base32hex_encode(&nc_n3.next_hashed_owner),
    ))
}

/// Verifies an authenticated NODATA proof (including proving a delegation has no DS record).
pub fn verify_nodata(
    qname: &DnsName,
    qtype: u16,
    zone: &DnsName,
    verified_records: &[Record],
) -> Result<String, String> {
    let nsecs = extract_nsecs(verified_records);
    if !nsecs.is_empty() {
        return verify_nodata_nsec(qname, qtype, zone, &nsecs);
    }
    let nsec3s = extract_nsec3s(verified_records, zone);
    if !nsec3s.is_empty() {
        return verify_nodata_nsec3(qname, qtype, zone, &nsec3s);
    }
    Err(format!(
        "NODATA for {qname} (type {qtype}) lacks verified NSEC or NSEC3 records"
    ))
}

fn verify_nodata_nsec(
    qname: &DnsName,
    qtype: u16,
    zone: &DnsName,
    nsecs: &[(&DnsName, &NsecData)],
) -> Result<String, String> {
    // Exact owner match: name exists, qtype (and CNAME) must be absent from type bitmap
    if let Some((owner, nsec)) = nsecs.iter().copied().find(|(owner, _)| **owner == *qname) {
        if nsec.has_type(qtype) {
            return Err(format!("NSEC at {owner} claims requested type {qtype} exists"));
        }
        if qtype != TYPE_CNAME && nsec.has_type(TYPE_CNAME) {
            return Err(format!("NSEC at {owner} has CNAME set for NODATA response"));
        }
        if qtype == TYPE_DS && nsec.has_type(TYPE_SOA) {
            return Err(format!("NSEC at {owner} has SOA set; not a child delegation cut"));
        }
        return Ok(format!(
            "NSEC at {owner} proves type {} is absent",
            crate::rdata::type_name(qtype)
        ));
    }

    // Empty Non-Terminal (ENT): qname is strictly covered and is an ancestor of next_domain_name
    for (owner, nsec) in nsecs {
        if nsec_covers(owner, &nsec.next_domain_name, qname, zone)
            && nsec.next_domain_name.is_subdomain_of(qname)
        {
            return Ok(format!(
                "NSEC ({owner} -> {}) proves {qname} is an empty non-terminal with no {} record",
                nsec.next_domain_name,
                crate::rdata::type_name(qtype)
            ));
        }
    }

    // Also allow wildcard NODATA or non-existent name proof when proving missing DS on non-delegation
    if let Some((owner, nsec)) = nsecs
        .iter()
        .copied()
        .find(|(owner, nsec)| nsec_covers(owner, &nsec.next_domain_name, qname, zone))
    {
        return Ok(format!(
            "NSEC ({owner} -> {}) covers {qname}, proving no {} record exists",
            nsec.next_domain_name,
            crate::rdata::type_name(qtype)
        ));
    }

    Err(format!(
        "no verified NSEC proves NODATA for {qname} type {}",
        crate::rdata::type_name(qtype)
    ))
}

fn verify_nodata_nsec3(
    qname: &DnsName,
    qtype: u16,
    zone: &DnsName,
    nsec3s: &[(Vec<u8>, &Nsec3Data)],
) -> Result<String, String> {
    let params = nsec3s[0].1;
    let qhash = nsec3_hash(qname, params.hash_algorithm, params.iterations, &params.salt)?;

    // Exact match: prove qtype and CNAME are not present in bitmap
    if let Some((owner_h, n3)) = nsec3s.iter().find(|(h, _)| *h == qhash) {
        if n3.has_type(qtype) {
            return Err(format!(
                "NSEC3 for {qname} ({}) claims type {qtype} exists",
                base32hex_encode(owner_h)
            ));
        }
        if qtype != TYPE_CNAME && n3.has_type(TYPE_CNAME) {
            return Err(format!("NSEC3 for {qname} has CNAME bit set"));
        }
        if qtype == TYPE_DS && n3.has_type(TYPE_SOA) {
            return Err(format!("NSEC3 for {qname} has SOA bit set; not a delegation cut"));
        }
        return Ok(format!(
            "NSEC3 exact match ({}) proves {} is absent for {qname}",
            base32hex_encode(owner_h),
            crate::rdata::type_name(qtype)
        ));
    }

    // RFC 5155 Section 7.2.7: Opt-Out proof for unsigned delegations (missing DS)
    if qtype == TYPE_DS {
        let mut candidate = qname.parent();
        let mut child = qname.clone();
        while let Some(anc) = candidate {
            if !anc.is_subdomain_of(zone) {
                break;
            }
            let ce_hash = nsec3_hash(&anc, params.hash_algorithm, params.iterations, &params.salt)?;
            if nsec3s.iter().any(|(h, _)| *h == ce_hash) {
                let nc_hash =
                    nsec3_hash(&child, params.hash_algorithm, params.iterations, &params.salt)?;
                if let Some((cov_h, cov_n3)) = nsec3s
                    .iter()
                    .find(|(h, n3)| nsec3_covers(h, &n3.next_hashed_owner, &nc_hash))
                {
                    if cov_n3.opt_out() {
                        return Ok(format!(
                            "NSEC3 Opt-Out ({}..{}) covers {child}, proving unsigned delegation (no DS)",
                            base32hex_encode(cov_h),
                            base32hex_encode(&cov_n3.next_hashed_owner)
                        ));
                    }
                }
            }
            child = anc.clone();
            candidate = anc.parent();
        }
    }

    // Fallback: closest encloser + covered next closer proves qname itself does not exist (thus no qtype)
    if let Ok(msg) = verify_nxdomain_nsec3(qname, zone, nsec3s) {
        return Ok(msg);
    }

    Err(format!(
        "no verified NSEC3 proves NODATA for {qname} type {}",
        crate::rdata::type_name(qtype)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::{TYPE_A, TYPE_NSEC, TYPE_RRSIG};
    use crate::wire::CLASS_IN;

    #[test]
    fn nsec3_hash_matches_rfc5155_appendix_a() {
        // RFC 5155 Appendix A test vector: salt = aabbccdd, iterations = 12, alg = 1 (SHA-1)
        // example. -> 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
        // a.example. -> 35mthgpgcu1qg68fab165klnsnk3dpvl
        // *.w.example. -> r53bq7cc2uvmubfu5ocmm6pers9tk9en
        let salt = [0xAAu8, 0xBBu8, 0xCCu8, 0xDDu8];
        let example = DnsName::parse_str("example.").unwrap();
        let h1 = nsec3_hash(&example, 1, 12, &salt).unwrap();
        assert_eq!(base32hex_encode(&h1), "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM");

        let a_example = DnsName::parse_str("a.example.").unwrap();
        let h2 = nsec3_hash(&a_example, 1, 12, &salt).unwrap();
        assert_eq!(base32hex_encode(&h2), "35MTHGPGCU1QG68FAB165KLNSNK3DPVL");

        let wc = DnsName::parse_str("*.w.example.").unwrap();
        let h3 = nsec3_hash(&wc, 1, 12, &salt).unwrap();
        assert_eq!(base32hex_encode(&h3), "R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN");
    }

    #[test]
    fn nsec_coverage_and_nxdomain_proof() {
        let zone = DnsName::parse_str("lab.test.").unwrap();
        let r1 = Record {
            name: DnsName::parse_str("lab.test.").unwrap(),
            rtype: TYPE_NSEC,
            rclass: CLASS_IN,
            ttl: 300,
            rdata: RData::Nsec(NsecData::new(
                DnsName::parse_str("alpha.lab.test.").unwrap(),
                vec![TYPE_NS, TYPE_SOA, TYPE_RRSIG, TYPE_NSEC],
            )),
        };
        let r2 = Record {
            name: DnsName::parse_str("alpha.lab.test.").unwrap(),
            rtype: TYPE_NSEC,
            rclass: CLASS_IN,
            ttl: 300,
            rdata: RData::Nsec(NsecData::new(
                DnsName::parse_str("www.lab.test.").unwrap(),
                vec![TYPE_A, TYPE_RRSIG, TYPE_NSEC],
            )),
        };

        // ghost.lab.test. falls between alpha.lab.test. and www.lab.test.; *.lab.test. falls between lab.test. and alpha.lab.test.
        let ghost = DnsName::parse_str("ghost.lab.test.").unwrap();
        let proof = verify_nxdomain(&ghost, &zone, &[r1, r2]);
        assert!(proof.is_ok(), "expected valid NSEC NXDOMAIN proof: {proof:?}");
    }
}
