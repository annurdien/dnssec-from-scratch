use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair, RsaPublicKeyComponents, UnparsedPublicKey};

use crate::rdata::{algorithm_name, type_name, DnskeyData, DsData, RData, RrsigData};
use crate::wire::{DnsName, Record};

#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    pub key_tag: u16,
    pub algorithm: u8,
    pub signer_name: DnsName,
    pub inception: u32,
    pub expiration: u32,
}

/// Computes the RFC 4034 Appendix B Key Tag for a DNSKEY record.
pub fn compute_key_tag(dnskey: &DnskeyData) -> u16 {
    let rdata = dnskey.to_wire();
    if dnskey.algorithm == 1 {
        // Legacy RSAMD5 special case (RFC 4034 Appendix B.1)
        if rdata.len() < 3 {
            return 0;
        }
        return u16::from_be_bytes([rdata[rdata.len() - 3], rdata[rdata.len() - 2]]);
    }

    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 1 {
            ac += byte as u32;
        } else {
            ac += (byte as u32) << 8;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

/// Computes a DS digest per RFC 4034 Section 5.1.4:
/// digest = H(canonical_owner_wire || flags || protocol || algorithm || public_key)
pub fn compute_ds_digest(
    owner: &DnsName,
    dnskey: &DnskeyData,
    digest_type: u8,
) -> Result<Vec<u8>, String> {
    let alg = match digest_type {
        1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        2 => &digest::SHA256,
        4 => &digest::SHA384,
        other => return Err(format!("unsupported DS digest type: {other}")),
    };

    let mut ctx = digest::Context::new(alg);
    ctx.update(&owner.to_canonical_wire());
    ctx.update(&dnskey.to_wire());
    Ok(ctx.finish().as_ref().to_vec())
}

/// Builds a DS record from an owner name, DNSKEY, and digest type.
pub fn make_ds(owner: &DnsName, dnskey: &DnskeyData, digest_type: u8) -> Result<DsData, String> {
    Ok(DsData {
        key_tag: compute_key_tag(dnskey),
        algorithm: dnskey.algorithm,
        digest_type,
        digest: compute_ds_digest(owner, dnskey, digest_type)?,
    })
}

/// Checks if a DNSKEY matches any DS record in the trusted parent DS set.
pub fn match_dnskey_against_ds<'a>(
    zone: &DnsName,
    dnskeys: &'a [DnskeyData],
    ds_set: &[DsData],
) -> Vec<(&'a DnskeyData, DsData)> {
    let mut matches = Vec::new();
    for ds in ds_set {
        for key in dnskeys {
            if key.protocol != 3 || !key.is_zone_key() || key.is_revoked() {
                continue;
            }
            if key.algorithm != ds.algorithm {
                continue;
            }
            if compute_key_tag(key) != ds.key_tag {
                continue;
            }
            if let Ok(calculated) = compute_ds_digest(zone, key, ds.digest_type) {
                if calculated == ds.digest {
                    matches.push((key, ds.clone()));
                }
            }
        }
    }
    matches
}

/// RFC 1982 serial number arithmetic comparison: returns true if `a <= b` in 32-bit wrap space.
pub fn serial_le(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

pub fn verify_rrsig_window(rrsig: &RrsigData, now_unix: u32) -> Result<(), String> {
    if !serial_le(rrsig.inception, now_unix) {
        return Err(format!(
            "RRSIG inception {} is in the future (now={})",
            rrsig.inception, now_unix
        ));
    }
    if !serial_le(now_unix, rrsig.expiration) {
        return Err(format!(
            "RRSIG expired at {} (now={})",
            rrsig.expiration, now_unix
        ));
    }
    Ok(())
}

/// Constructs the exact byte buffer covered by an RRSIG per RFC 4034 Section 3.1.8.1 & RFC 4035 Section 5.3.2.
pub fn build_rrsig_signed_data(rrsig: &RrsigData, rrset: &[Record]) -> Result<Vec<u8>, String> {
    if rrset.is_empty() {
        return Err("cannot verify an empty RRset".to_string());
    }

    let owner = &rrset[0].name;
    let rtype = rrset[0].rtype;
    let rclass = rrset[0].rclass;

    if rtype != rrsig.type_covered {
        return Err(format!(
            "RRSIG covers {}, not {}",
            type_name(rrsig.type_covered),
            type_name(rtype)
        ));
    }

    for rr in rrset {
        if rr.name != *owner || rr.rtype != rtype || rr.rclass != rclass {
            return Err("RRset contains mismatched owner, type, or class".to_string());
        }
    }

    let owner_labels = owner.rrsig_label_count() as usize;
    let sig_labels = rrsig.labels as usize;
    let effective_owner = if owner_labels == sig_labels {
        owner.clone()
    } else if owner_labels > sig_labels {
        owner
            .wildcard_with_suffix_labels(sig_labels)
            .ok_or_else(|| "invalid wildcard label count in RRSIG".to_string())?
    } else {
        return Err(format!(
            "RRSIG labels ({sig_labels}) exceeds owner label count ({owner_labels}) for {owner}"
        ));
    };

    let owner_wire = effective_owner.to_canonical_wire();

    let mut canonical_rdatas: Vec<Vec<u8>> = rrset
        .iter()
        .map(|rr| rr.rdata.to_canonical_rdata())
        .collect();
    canonical_rdatas.sort();
    canonical_rdatas.dedup();

    let mut data = rrsig.signed_prefix_wire();
    for rdata in canonical_rdatas {
        let rdlen = u16::try_from(rdata.len())
            .map_err(|_| "canonical RDATA length overflows u16".to_string())?;
        data.extend_from_slice(&owner_wire);
        data.extend_from_slice(&rtype.to_be_bytes());
        data.extend_from_slice(&rclass.to_be_bytes());
        data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        data.extend_from_slice(&rdlen.to_be_bytes());
        data.extend_from_slice(&rdata);
    }

    Ok(data)
}

/// Verifies raw signature bytes against a DNSKEY public key using `ring`.
pub fn verify_raw_signature(
    dnskey: &DnskeyData,
    signed_data: &[u8],
    sig_bytes: &[u8],
) -> Result<(), String> {
    if dnskey.protocol != 3 {
        return Err(format!("invalid DNSKEY protocol {}", dnskey.protocol));
    }
    if !dnskey.is_zone_key() {
        return Err("DNSKEY does not have Zone Key flag (bit 7 / 256) set".to_string());
    }
    if dnskey.is_revoked() {
        return Err("DNSKEY is revoked".to_string());
    }

    match dnskey.algorithm {
        8 | 10 => {
            let (e, n) = parse_rfc3110_rsa_key(&dnskey.public_key)?;
            let components = RsaPublicKeyComponents { n, e };
            let alg: &signature::RsaParameters = match (dnskey.algorithm, n.len() >= 256) {
                (8, true) => &signature::RSA_PKCS1_2048_8192_SHA256,
                (8, false) => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                (10, true) => &signature::RSA_PKCS1_2048_8192_SHA512,
                (10, false) => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                _ => unreachable!(),
            };
            components
                .verify(alg, signed_data, sig_bytes)
                .map_err(|_| format!("{} signature verification failed", algorithm_name(dnskey.algorithm)))
        }
        13 => {
            if dnskey.public_key.len() != 64 {
                return Err(format!(
                    "ECDSAP256SHA256 key must be 64 bytes, got {}",
                    dnskey.public_key.len()
                ));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&dnskey.public_key);
            let pubkey = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &sec1);
            pubkey
                .verify(signed_data, sig_bytes)
                .map_err(|_| "ECDSAP256SHA256 signature verification failed".to_string())
        }
        14 => {
            if dnskey.public_key.len() != 96 {
                return Err(format!(
                    "ECDSAP384SHA384 key must be 96 bytes, got {}",
                    dnskey.public_key.len()
                ));
            }
            let mut sec1 = Vec::with_capacity(97);
            sec1.push(0x04);
            sec1.extend_from_slice(&dnskey.public_key);
            let pubkey = UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &sec1);
            pubkey
                .verify(signed_data, sig_bytes)
                .map_err(|_| "ECDSAP384SHA384 signature verification failed".to_string())
        }
        15 => {
            if dnskey.public_key.len() != 32 {
                return Err(format!(
                    "ED25519 key must be 32 bytes, got {}",
                    dnskey.public_key.len()
                ));
            }
            let pubkey = UnparsedPublicKey::new(&signature::ED25519, &dnskey.public_key);
            pubkey
                .verify(signed_data, sig_bytes)
                .map_err(|_| "ED25519 signature verification failed".to_string())
        }
        other => Err(format!(
            "unsupported DNSSEC algorithm {other} ({})",
            algorithm_name(other)
        )),
    }
}

/// Parses RFC 3110 Section 2 RSA DNSKEY public key wire format: (exponent, modulus).
fn parse_rfc3110_rsa_key(key: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if key.len() < 3 {
        return Err("RSA DNSKEY public key too short".to_string());
    }
    let (exp_len, exp_start) = if key[0] == 0 {
        if key.len() < 4 {
            return Err("RSA DNSKEY 3-byte exponent length truncated".to_string());
        }
        (u16::from_be_bytes([key[1], key[2]]) as usize, 3usize)
    } else {
        (key[0] as usize, 1usize)
    };
    if exp_len == 0 || exp_start + exp_len >= key.len() {
        return Err("invalid RSA DNSKEY exponent bounds".to_string());
    }
    let e = &key[exp_start..exp_start + exp_len];
    let n = &key[exp_start + exp_len..];
    Ok((e, n))
}

/// Verifies an RRset against candidate RRSIGs and trusted DNSKEYs for `expected_signer`.
pub fn verify_rrset(
    rrset: &[Record],
    rrsigs: &[RrsigData],
    dnskeys: &[DnskeyData],
    expected_signer: &DnsName,
    now_unix: u32,
) -> Result<VerifiedSignature, String> {
    if rrset.is_empty() {
        return Err("empty RRset".to_string());
    }
    let rtype = rrset[0].rtype;
    let owner = &rrset[0].name;

    let matching_sigs: Vec<&RrsigData> = rrsigs
        .iter()
        .filter(|sig| sig.type_covered == rtype && sig.signer_name == *expected_signer)
        .collect();

    if matching_sigs.is_empty() {
        return Err(format!(
            "no RRSIG covering {} {} signed by {}",
            owner,
            type_name(rtype),
            expected_signer
        ));
    }

    let mut errors = Vec::new();
    for sig in matching_sigs {
        if let Err(e) = verify_rrsig_window(sig, now_unix) {
            errors.push(format!("tag {}: {e}", sig.key_tag));
            continue;
        }
        let signed_data = match build_rrsig_signed_data(sig, rrset) {
            Ok(d) => d,
            Err(e) => {
                errors.push(format!("tag {}: {e}", sig.key_tag));
                continue;
            }
        };

        let mut matched_key = false;
        for key in dnskeys {
            if key.algorithm != sig.algorithm || compute_key_tag(key) != sig.key_tag {
                continue;
            }
            matched_key = true;
            match verify_raw_signature(key, &signed_data, &sig.signature) {
                Ok(()) => {
                    return Ok(VerifiedSignature {
                        key_tag: sig.key_tag,
                        algorithm: sig.algorithm,
                        signer_name: sig.signer_name.clone(),
                        inception: sig.inception,
                        expiration: sig.expiration,
                    });
                }
                Err(e) => errors.push(format!("tag {}: {e}", sig.key_tag)),
            }
        }
        if !matched_key {
            errors.push(format!(
                "no trusted DNSKEY matching tag={} alg={}",
                sig.key_tag, sig.algorithm
            ));
        }
    }

    Err(format!(
        "RRSIG verification failed for {} {}: {}",
        owner,
        type_name(rtype),
        errors.join("; ")
    ))
}

/// Generates an ephemeral ECDSA P-256 (Algorithm 13) key pair and matching DNSKEY record for the local lab.
pub fn generate_ecdsa_p256_key(sep: bool) -> Result<(EcdsaKeyPair, DnskeyData), String> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| "failed to generate ECDSA P-256 keypair".to_string())?;
    let keypair = EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .map_err(|_| "failed to load ECDSA P-256 keypair".to_string())?;

    let pub_bytes = keypair.public_key().as_ref();
    if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
        return Err("unexpected ECDSA P-256 uncompressed public key format".to_string());
    }

    let flags = if sep { 257 } else { 256 };
    let dnskey = DnskeyData {
        flags,
        protocol: 3,
        algorithm: 13,
        public_key: pub_bytes[1..].to_vec(),
    };
    Ok((keypair, dnskey))
}

/// Signs an RRset using an ECDSA P-256 key pair and returns the corresponding RRSIG record.
pub fn sign_rrset_ecdsa_p256(
    rrset: &[Record],
    signer_name: &DnsName,
    keypair: &EcdsaKeyPair,
    dnskey: &DnskeyData,
    inception: u32,
    expiration: u32,
) -> Result<Record, String> {
    if rrset.is_empty() {
        return Err("cannot sign empty RRset".to_string());
    }
    let owner = rrset[0].name.clone();
    let rtype = rrset[0].rtype;
    let rclass = rrset[0].rclass;
    let ttl = rrset[0].ttl;

    let mut rrsig = RrsigData {
        type_covered: rtype,
        algorithm: 13,
        labels: owner.rrsig_label_count(),
        original_ttl: ttl,
        expiration,
        inception,
        key_tag: compute_key_tag(dnskey),
        signer_name: signer_name.clone(),
        signature: Vec::new(),
    };

    let signed_data = build_rrsig_signed_data(&rrsig, rrset)?;
    let rng = SystemRandom::new();
    let sig = keypair
        .sign(&rng, &signed_data)
        .map_err(|_| "ECDSA P-256 signing failed".to_string())?;
    rrsig.signature = sig.as_ref().to_vec();

    Ok(Record {
        name: owner,
        rtype: crate::rdata::TYPE_RRSIG,
        rclass,
        ttl,
        rdata: RData::Rrsig(rrsig),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::TYPE_A;
    use crate::wire::CLASS_IN;
    use std::net::Ipv4Addr;

    #[test]
    fn ecdsa_p256_sign_verify_and_tamper_detection() {
        let zone = DnsName::parse_str("lab.test.").unwrap();
        let owner = DnsName::parse_str("www.lab.test.").unwrap();
        let (kp, dnskey) = generate_ecdsa_p256_key(false).unwrap();

        let rrset = vec![Record {
            name: owner.clone(),
            rtype: TYPE_A,
            rclass: CLASS_IN,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(198, 51, 100, 42)),
        }];

        let sig_rec = sign_rrset_ecdsa_p256(&rrset, &zone, &kp, &dnskey, 1_700_000_000, 1_900_000_000)
            .unwrap();
        let sig_data = match sig_rec.rdata {
            RData::Rrsig(s) => s,
            _ => unreachable!(),
        };

        // Valid verification succeeds
        let ok = verify_rrset(&rrset, &[sig_data.clone()], &[dnskey.clone()], &zone, 1_750_000_000);
        assert!(ok.is_ok());

        // Tampering with 1 byte of the IP fails verification
        let mut tampered = rrset.clone();
        tampered[0].rdata = RData::A(Ipv4Addr::new(198, 51, 100, 43));
        assert!(verify_rrset(&tampered, &[sig_data.clone()], &[dnskey.clone()], &zone, 1_750_000_000).is_err());

        // Expired timestamp fails verification
        assert!(verify_rrset(&rrset, &[sig_data], &[dnskey], &zone, 1_950_000_000).is_err());
    }

    #[test]
    fn ds_digest_matches_dnskey() {
        let zone = DnsName::parse_str("example.org.").unwrap();
        let (_, ksk) = generate_ecdsa_p256_key(true).unwrap();
        let ds = make_ds(&zone, &ksk, 2).unwrap();
        assert_eq!(ds.digest.len(), 32);
        let keys = [ksk];
        let ds_list = [ds];
        let matches = match_dnskey_against_ds(&zone, &keys, &ds_list);
        assert_eq!(matches.len(), 1);
    }
}
