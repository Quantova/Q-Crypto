// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Throughput benchmark for the post quantum primitives.

use std::hint::black_box;
use std::time::{Duration, Instant};

use qtv_crypto::{chacha20poly1305, ml_dsa, ml_kem, sha3, slh_dsa};

fn report(name: &str, iters: u32, elapsed: Duration) {
    let seconds = elapsed.as_secs_f64();
    let per_op = seconds / f64::from(iters);
    let per_second = f64::from(iters) / seconds;
    println!(
        "{:<16} {:>16.3} us/op {:>16.2} ops/s",
        name,
        per_op * 1.0e6,
        per_second
    );
}

fn main() {
    // sha3_256 on a one kilobyte input.
    {
        let input = [90u8; 1024];
        let iters = 200_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(sha3::sha3_256(black_box(&input)));
        }
        report("sha3_256", iters, start.elapsed());
    }

    // ml_dsa keygen, sign, and verify.
    let mldsa_seed = [17u8; 32];
    {
        let iters = 2_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(ml_dsa::keygen(black_box(&mldsa_seed)));
        }
        report("ml_dsa_keygen", iters, start.elapsed());
    }
    let (mldsa_pk, mldsa_sk) = ml_dsa::keygen(&mldsa_seed);
    let mldsa_msg = [34u8; 64];
    let mldsa_ctx: [u8; 0] = [];
    let mldsa_rnd = [51u8; 32];
    {
        let iters = 1_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(ml_dsa::sign(&mldsa_sk, &mldsa_msg, &mldsa_ctx, &mldsa_rnd));
        }
        report("ml_dsa_sign", iters, start.elapsed());
    }
    let mldsa_sig = ml_dsa::sign(&mldsa_sk, &mldsa_msg, &mldsa_ctx, &mldsa_rnd)
        .expect("empty context signs");
    {
        let iters = 4_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(ml_dsa::verify(&mldsa_pk, &mldsa_msg, &mldsa_sig, &mldsa_ctx));
        }
        report("ml_dsa_verify", iters, start.elapsed());
    }

    // ml_kem keygen, encaps, and decaps.
    let kem_d = [68u8; 32];
    let kem_z = [85u8; 32];
    {
        let iters = 10_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(ml_kem::keygen(black_box(&kem_d), black_box(&kem_z)));
        }
        report("ml_kem_keygen", iters, start.elapsed());
    }
    let (kem_ek, kem_dk) = ml_kem::keygen(&kem_d, &kem_z);
    let kem_m = [102u8; 32];
    {
        let iters = 10_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(ml_kem::encaps(&kem_ek, black_box(&kem_m)));
        }
        report("ml_kem_encaps", iters, start.elapsed());
    }
    let (_kem_ss, kem_ct) = ml_kem::encaps(&kem_ek, &kem_m).expect("encaps");
    {
        let iters = 10_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(ml_kem::decaps(&kem_dk, black_box(&kem_ct)));
        }
        report("ml_kem_decaps", iters, start.elapsed());
    }

    // slh_dsa keygen, sign, and verify. Signing is slow, so the iteration counts stay small.
    let slh_sk_seed = [119u8; 24];
    let slh_sk_prf = [136u8; 24];
    let slh_pk_seed = [153u8; 24];
    {
        let iters = 20u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(slh_dsa::keygen(&slh_sk_seed, &slh_sk_prf, &slh_pk_seed));
        }
        report("slh_dsa_keygen", iters, start.elapsed());
    }
    let (slh_sk, slh_pk) = slh_dsa::keygen(&slh_sk_seed, &slh_sk_prf, &slh_pk_seed);
    let slh_msg = [170u8; 64];
    let slh_ctx: [u8; 0] = [];
    let slh_addrnd = [187u8; 24];
    {
        let iters = 5u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(slh_dsa::sign(&slh_sk, &slh_msg, &slh_ctx, &slh_addrnd));
        }
        report("slh_dsa_sign", iters, start.elapsed());
    }
    let slh_sig = slh_dsa::sign(&slh_sk, &slh_msg, &slh_ctx, &slh_addrnd)
        .expect("empty context signs");
    {
        let iters = 100u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(slh_dsa::verify(&slh_pk, &slh_msg, &slh_sig, &slh_ctx));
        }
        report("slh_dsa_verify", iters, start.elapsed());
    }

    // chacha20poly1305 seal and open on a one kilobyte payload.
    let aead_key = [221u8; 32];
    let aead_nonce = [238u8; 12];
    let aead_aad = [1u8; 16];
    let aead_pt = [90u8; 1024];
    {
        let iters = 100_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(chacha20poly1305::seal(
                &aead_key,
                &aead_nonce,
                &aead_aad,
                &aead_pt,
            ));
        }
        report("chacha20_seal", iters, start.elapsed());
    }
    let (aead_ct, aead_tag) = chacha20poly1305::seal(&aead_key, &aead_nonce, &aead_aad, &aead_pt);
    {
        let iters = 100_000u32;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(chacha20poly1305::open(
                &aead_key,
                &aead_nonce,
                &aead_aad,
                &aead_ct,
                &aead_tag,
            ));
        }
        report("chacha20_open", iters, start.elapsed());
    }
}
