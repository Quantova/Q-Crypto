//! qtv-crypto - the single source of cryptography in the Quantova organization.
//!
//! The cryptography POLICY-crypto.md permits and nothing else: the NIST post-quantum algorithms and
//! the single 256-bit symmetric AEAD the policy allows, ChaCha20-Poly1305 (RFC 8439). No classical
//! public-key cryptography is representable. Every primitive is implemented from its specification
//! and validated against the official known-answer tests.
//!
//! Implementation order (each gates the next): sha3, then ml_dsa, then ml_kem, then slh_dsa, then
//! the two VRF constructions. `vrf` is the hash-based VRF on slh_dsa and `vrf_mldsa` is the
//! lattice-based VRF on ml_dsa; both are kept. The symmetric AEAD in chacha20poly1305 stands alone
//! and depends on nothing else here.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod chacha20poly1305;
pub mod ml_dsa;
pub mod ml_kem;
pub mod sha3;
pub mod slh_dsa;
pub mod vrf;
pub mod vrf_mldsa;

#[cfg(feature = "fn-dsa")]
pub mod fn_dsa;
