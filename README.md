# Q-Crypto

Q-Crypto is the cryptographic floor of Quantova, a sovereign post quantum Layer 1 built from scratch with no classical escape hatch anywhere. It is the only cryptography in the organization. Every signature the chain checks, every key exchange the transport runs, every committee draw the consensus samples, and every crypto opcode the virtual machine executes calls into this one crate. There is no second implementation and no vendored library behind it.

## What it is

A from scratch reference implementation of the NIST post quantum standards, written against the published FIPS documents and validated against the official NIST known answer tests. The crate is built on the Rust standard library alone. It pulls in no third party dependency, no RustCrypto, no OpenSSL, nothing. What checks a signature on Quantova is code you can read in this repository, end to end, from the Keccak permutation up.

Classical public key cryptography is not merely absent, it is unrepresentable. There is no elliptic curve, no ECDSA, no secp256k1, no Ed25519, no X25519, no RSA, no pairing. A machine readable deny list in `deny.toml` bans those crates from anywhere in the dependency tree, transitive and dev dependencies included, and CI runs `cargo deny` on every change.

Q-Crypto is a reference implementation validated against NIST test vectors. It has not been independently audited. It is not described as production secure, and it is not marketed as unbreakable.

## The primitives

Each primitive is implemented in dependency order, and each one gates the next.

- **SHA-3 and SHAKE** (FIPS 202). The Keccak sponge, SHA3-256, SHA3-512, SHAKE128, and SHAKE256. Implemented first because every other primitive builds on it.
- **ML-DSA-65** (FIPS 204, security category 3). The stack's primary signature scheme, used for account signing, validator attestation, and the virtual machine verify opcode. A 1952 byte public key, a 4032 byte secret key, and a 3309 byte signature. Full number theoretic transform, rejection sampling, bit packing, and the hint mechanism, all hashing through SHAKE.
- **ML-KEM-768** (FIPS 203, security category 3). Module lattice key encapsulation. It backs the transport key exchange, an ML-KEM plus ML-DSA handshake with no X25519. A 1184 byte encapsulation key, a 2400 byte decapsulation key, and a 1088 byte ciphertext.
- **SLH-DSA-SHAKE-192s** (FIPS 205, security category 3). Stateless hash based signatures, the conservative option whose security rests on the hash alone. The small parameter set, a 48 byte public key against a 16224 byte signature.
- **ChaCha20-Poly1305** (RFC 8439). The single 256 bit symmetric AEAD the crypto policy permits, used by the transport. It stands alone and depends on nothing else in the crate.

FN-DSA (FIPS 206) is present but feature flagged off behind `fn-dsa`, and it stays off until the standard is published in final form and the cryptographic transition track admits it.

## Build and test

```
cargo test
cargo deny check
cargo bench
```

The signature and KEM schemes are checked end to end against the official NIST vectors committed under `vectors/`, keygen and sign and verify for ML-DSA, keygen and encaps and decaps for ML-KEM, the SLH-DSA vectors, the SHA-3 and SHAKE known answers, and the RFC 8439 vectors for the AEAD, alongside rejection tests that a tampered ciphertext, tag, nonce, or key fails to open.

## Where it sits in the stack

Every other repository depends on this crate, pinned by git tag rather than a registry version. The QVM verify and hash and KEM opcodes call these primitives directly. Quantova-Chain signs accounts and transactions with ML-DSA and runs its transport handshake on ML-KEM. QORUS aggregates validator attestations over ML-DSA and derives its committee sortition and randomness beacon from SHA-3 and SHAKE. The address format commits to an ML-DSA public key, never to a truncated hash of an elliptic curve key.

## Status

At testnet. The stack pins the released `v0.3.0` tag. The crate is a reference implementation validated against NIST test vectors and has not been independently audited.

## License

Dual licensed under Apache 2.0 and MIT. See `LICENSE-APACHE` and `LICENSE-MIT`.
