# dnssec-from-scratch

A standalone DNSSEC chain-of-trust validator, NSEC/NSEC3 negative-proof verifier, and local tampering lab written in Rust.

Everything above raw cryptographic primitives (`ring`) is built directly on `std`: DNS wire packet encoding/decoding, RFC 1035 pointer compression, EDNS0 (`DO=1`) with automatic TCP fallback on `TC=1`, RFC 4034 key tag and canonical RRset ordering, DS digest chaining from the IANA root trust anchors, RRSIG verification (RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519), NSEC/NSEC3 authenticated denial of existence, and a local two-tier signed lab server.

## Quick start

Run the full offline local lab (spawns ephemeral ECDSA P-256 root and leaf servers on loopback UDP/TCP and tests tampering, stripping, expiration, DS mismatches, unsigned delegations, NSEC, and NSEC3):

```bash
cargo run -- demo
```

Inspect a single local tampering run with full chain-of-trust trace:

```bash
cargo run -- lab-once tamper-ip api.lab.test
cargo run -- lab-once nsec3 ghost.lab.test
```

Walk an NSEC chain locally to see why plain NSEC exposes every hostname in a zone:

```bash
cargo run -- lab-walk
```

Verify live internet domains straight from the IANA root servers (no local recursive resolver):

```bash
cargo run -- verify iana.org A
cargo run -- verify cloudflare.com A
cargo run -- verify dnssec-failed.org A
cargo run -- verify nonexistent.iana.org A
```

Run unit and integration tests:

```bash
cargo test
```

## Module layout

- `src/wire.rs` : DNS packet codec, label compression, EDNS0 `OPT`, canonical DNS name ordering
- `src/rdata.rs` : RDATA parsers, canonical serializers, and NSEC/NSEC3 type bitmap codec
- `src/transport.rs` : Raw `std::net` UDP socket client with automatic TCP fallback on truncation
- `src/crypto.rs` : RFC 4034 key tag, DS digests, RRSIG signed payload builder, `ring` verification and ECDSA P-256 lab signer
- `src/nsec.rs` : Base32hex, iterative SHA-1 NSEC3 hashing, NSEC/NSEC3 NXDOMAIN and NODATA (including Opt-Out) proofs
- `src/resolver.rs` : Iterative root-to-leaf DNSSEC chain walker, glueless NS resolution, CNAME following, and NSEC walker
- `src/lab.rs` : Two-tier local authoritative DNSSEC server with live tampering modes
- `src/main.rs` : CLI entry point
