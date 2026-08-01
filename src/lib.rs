// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


#![forbid(unsafe_op_in_unsafe_fn)]

pub mod chacha20poly1305;
pub mod ml_dsa;
pub mod ml_kem;
pub mod sha3;
pub mod slh_dsa;

mod zeroize;

#[cfg(feature = "os-rng")]
mod rng;

#[cfg(feature = "os-rng")]
pub use ml_dsa::{keygen_os as ml_dsa_keygen_os, sign_os as ml_dsa_sign_os};
#[cfg(feature = "os-rng")]
pub use ml_kem::{encaps_os as ml_kem_encaps_os, keygen_os as ml_kem_keygen_os};
#[cfg(feature = "os-rng")]
pub use slh_dsa::{keygen_os as slh_dsa_keygen_os, sign_os as slh_dsa_sign_os};

#[cfg(feature = "fn-dsa")]
pub mod fn_dsa;
