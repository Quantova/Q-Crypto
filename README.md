# Q-Crypto

Quantova is a sovereign post quantum Layer 1, built from scratch, sharing no code, no wire format, and no trust assumption with any other chain. It is post quantum end to end, not a classical chain with a post quantum signature bolted on. Every layer is its own, and every layer stands on NIST standardized schemes with no classical escape hatch anywhere.

Q-Crypto is that cryptographic floor. It is the only cryptography in the organization. Every signature the chain checks, every key exchange the transport runs, every committee draw the consensus samples, and every crypto opcode the virtual machine executes calls into this one crate. There is no second implementation and no vendored library behind it.

## What it is

A from scratch reference implementation of the NIST post quantum standards, written against the published FIPS documents and validated against the official NIST known answer tests. The crate is built on the Rust standard library alone. It pulls in no third party dependency, no RustCrypto, no OpenSSL, nothing. What checks a signature on Quantova is code you can read in this repository, end to end, from the Keccak permutation up.

Classical public key cryptography is not merely absent, it is unrepresentable. There is no elliptic curve, no ECDSA, no secp256k1, no Ed25519, no X25519, no RSA, no pairing. A machine readable deny list in `deny.toml` bans those crates from anywhere in the dependency tree, transitive and dev dependencies included, and CI runs `cargo deny` on every change.

Q-Crypto is a reference implementation validated against NIST test vectors. It has not been independently audited. It is not described as production secure, and it is not marketed as unbreakable.

## The primitives

Each primitive is implemented in dependency order, and each one gates the next.

- **SHA-3 and SHAKE** (FIPS 202). The Keccak sponge, SHA3-256, SHA3-512, SHAKE128, and SHAKE256. Implemented first because every other primitive and both VRFs build on it.
- **ML-DSA-65** (FIPS 204, security category 3). The stack's primary signature scheme, used for account signing, validator attestation, and the virtual machine verify opcode. A 1952 byte public key, a 4032 byte secret key, and a 3309 byte signature. Full number theoretic transform, rejection sampling, bit packing, and the hint mechanism, all hashing through SHAKE.
- **ML-KEM-768** (FIPS 203, security category 3). Module lattice key encapsulation. It backs the transport key exchange, an ML-KEM plus ML-DSA handshake with no X25519. A 1184 byte encapsulation key, a 2400 byte decapsulation key, and a 1088 byte ciphertext.
- **SLH-DSA-SHAKE-192s** (FIPS 205, security category 3). Stateless hash based signatures, the conservative option whose security rests on the hash alone. The small parameter set, a 48 byte public key against a 16224 byte signature.
- **Two post quantum verifiable random functions.** One hash based on SLH-DSA, one lattice based on ML-DSA, on a shared interface. Both are deterministic signature functions reduced through SHAKE256 to a fixed 32 byte output, so the output is a fixed function of the key and input and is bound to the key by unforgeability. Both are kept, and the throughput benchmark decides which one consensus defaults to. No elliptic curve VRF is representable.
- **ChaCha20-Poly1305** (RFC 8439). The single 256 bit symmetric AEAD the crypto policy permits, used by the transport. It stands alone and depends on nothing else in the crate.

FN-DSA (FIPS 206) is present but feature flagged off behind `fn-dsa`, and it stays off until the standard is published in final form and the cryptographic transition track admits it.

## Build and test

```
cargo test
cargo deny check
cargo bench
```

The suite carries 48 tests. The signature and KEM schemes are checked end to end against the official NIST vectors committed under `vectors/`, keygen and sign and verify for ML-DSA, keygen and encaps and decaps for ML-KEM, the SLH-DSA vectors, the SHA-3 and SHAKE known answers, and the RFC 8439 vectors for the AEAD, alongside rejection tests that a tampered ciphertext, tag, nonce, or key fails to open. `benches/throughput.rs` measures per operation timing, and those numbers calibrate the gas schedule for the native crypto opcodes and the validator resource budget.

## Where it sits in the stack

Every other repository depends on this crate, pinned by git tag rather than a registry version. The QVM verify and hash and KEM opcodes call these primitives directly. Quantova-Chain signs accounts and transactions with ML-DSA and runs its transport handshake on ML-KEM. QORUS aggregates validator attestations over ML-DSA and derives its committee sortition and randomness beacon from SHA-3 and SHAKE, and the QVM `VRF_VERIFY` opcode checks the verifiable random function outputs. The address format commits to an ML-DSA public key, never to a truncated hash of an elliptic curve key.

## Status

At testnet. The stack pins the released `v0.3.0` tag. The crate is a reference implementation validated against NIST test vectors and has not been independently audited.

## License

Dual licensed under Apache 2.0 and MIT. See `LICENSE-APACHE` and `LICENSE-MIT`.
