//! qtv-crypto - the single source of cryptography in the Quantova organization.
//!
//! Only the NIST post-quantum algorithms named in POLICY-crypto.md exist here. No classical
//! cryptography is representable. Every primitive is implemented from its FIPS specification and
//! validated against the NIST known-answer tests in `vectors/`.
//!
//! Implementation order (each gates the next): sha3, then ml_dsa, then ml_kem, then slh_dsa, then vrf.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod sha3;
pub mod ml_dsa;
pub mod ml_kem;
pub mod slh_dsa;
pub mod vrf;

#[cfg(feature = "fn-dsa")]
pub mod fn_dsa;
