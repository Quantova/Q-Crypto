// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::assign_op_pattern)]

pub mod chacha20poly1305;
#[cfg(not(feature = "cnsa2"))]
pub mod ml_dsa;
pub mod ml_dsa_87;
#[cfg(not(feature = "cnsa2"))]
pub mod ml_kem;
pub mod ml_kem_1024;
pub mod sha2;
pub mod sha3;
pub mod slh_dsa;

#[cfg(feature = "cnsa2")]
#[path = "ml_dsa.rs"]
pub mod ml_dsa_65;
#[cfg(feature = "cnsa2")]
#[path = "ml_kem.rs"]
pub mod ml_kem_768;

#[cfg(feature = "cnsa2")]
pub mod ml_dsa {
    pub use crate::ml_dsa_87::*;
}

#[cfg(feature = "cnsa2")]
pub mod ml_kem {
    pub use crate::ml_kem_1024::*;
}

#[cfg(feature = "cnsa2")]
pub const PROFILE: &str = "CNSA 2.0, ML-DSA-87 and ML-KEM-1024";
#[cfg(not(feature = "cnsa2"))]
pub const PROFILE: &str = "category 3, ML-DSA-65 and ML-KEM-768";

mod zeroize;

pub use zeroize::SecretBytes;

#[cfg(feature = "os-rng")]
pub mod rng;

#[cfg(feature = "os-rng")]
pub use ml_dsa::{keygen_os as ml_dsa_keygen_os, sign_os as ml_dsa_sign_os};
#[cfg(feature = "os-rng")]
pub use ml_kem::{encaps_os as ml_kem_encaps_os, keygen_os as ml_kem_keygen_os};
#[cfg(feature = "os-rng")]
pub use slh_dsa::{keygen_os as slh_dsa_keygen_os, sign_os as slh_dsa_sign_os};
