//! ML-DSA (FIPS 204) - module-lattice digital signatures. The stack's primary signature scheme:
//! account signing, validator attestations, and the QVM `MLDSA_VERIFY` opcode.
//!
//! This first piece provides the ML-DSA-65 parameter set (FIPS 204, security category 3) together
//! with the polynomial arithmetic it is built on: the number theoretic transform, modular
//! reduction, the bit packing, and the rounding and hint helpers.

// The key generation, signing, and verification routines that consume this arithmetic land in the
// following piece, so the helpers below have no callers yet.
#![allow(dead_code)]

// Parameters for ML-DSA-65 (FIPS 204, Table 1).
const Q: i32 = 8380417; // prime modulus, 2^23 - 2^13 + 1
const N: usize = 256; // ring degree
const D: usize = 13; // number of dropped bits from t
const K: usize = 6; // rows of A
const L: usize = 5; // columns of A
const ETA: i32 = 4; // secret coefficient range
const TAU: usize = 49; // number of nonzero coefficients in the challenge
const BETA: i32 = 196; // TAU * ETA
const GAMMA1: i32 = 1 << 19; // coefficient range of the mask y
const GAMMA2: i32 = (Q - 1) / 32; // low-order rounding range
const OMEGA: usize = 55; // maximum number of ones in the hint
const LAMBDA: usize = 192; // collision strength in bits

// Derived encoding sizes.
const CTILDE_BYTES: usize = LAMBDA / 4; // 48
const POLYT1_PACKED: usize = 320; // 10 bits per coefficient
const POLYT0_PACKED: usize = 416; // 13 bits per coefficient
const POLYETA_PACKED: usize = 128; // 4 bits per coefficient
const POLYZ_PACKED: usize = 640; // 20 bits per coefficient
const POLYW1_PACKED: usize = 128; // 4 bits per coefficient

/// Encoded ML-DSA-65 public key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 32 + K * POLYT1_PACKED; // 1952
/// Encoded ML-DSA-65 secret key length in bytes.
pub const SECRET_KEY_BYTES: usize = 128 + (L + K) * POLYETA_PACKED + K * POLYT0_PACKED; // 4032
/// Encoded ML-DSA-65 signature length in bytes.
pub const SIGNATURE_BYTES: usize = CTILDE_BYTES + L * POLYZ_PACKED + OMEGA + K; // 3309
/// Length of the key generation seed in bytes.
pub const SEED_BYTES: usize = 32;

/// Encoded ML-DSA-65 public key.
pub type PublicKey = [u8; PUBLIC_KEY_BYTES];
/// Encoded ML-DSA-65 secret key.
pub type SecretKey = [u8; SECRET_KEY_BYTES];
/// Encoded ML-DSA-65 signature.
pub type Signature = [u8; SIGNATURE_BYTES];

// A ring element, represented by its 256 coefficients.
type Poly = [i32; N];

const ZERO_POLY: Poly = [0i32; N];

// Modular arithmetic over Z_q for inputs already reduced into [0, Q).

fn add_q(a: i32, b: i32) -> i32 {
    let r = a + b;
    if r >= Q {
        r - Q
    } else {
        r
    }
}

fn sub_q(a: i32, b: i32) -> i32 {
    let r = a - b;
    if r < 0 {
        r + Q
    } else {
        r
    }
}

fn mul_q(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64).rem_euclid(Q as i64)) as i32
}

// Map a small signed value in (-Q, Q) to its representative in [0, Q).
fn to_pos(a: i32) -> i32 {
    if a < 0 {
        a + Q
    } else {
        a
    }
}

// The centered representative of a in [0, Q), i.e. a mod +/- Q, in the range (-Q/2, Q/2].
fn center(a: i32) -> i32 {
    if a > (Q - 1) / 2 {
        a - Q
    } else {
        a
    }
}

// The infinity norm of a polynomial whose coefficients lie in [0, Q).
fn inf_norm(p: &Poly) -> i32 {
    let mut max = 0;
    for &c in p.iter() {
        let v = center(c).abs();
        if v > max {
            max = v;
        }
    }
    max
}

// Number theoretic transform tables.

// Bit reversal of the low eight bits of i.
const fn brv8(mut i: usize) -> u32 {
    let mut r = 0u32;
    let mut b = 0;
    while b < 8 {
        r = (r << 1) | (i & 1) as u32;
        i >>= 1;
        b += 1;
    }
    r
}

// base^exp mod Q for base in [0, Q).
const fn pow_mod(base: i64, mut exp: u32) -> i64 {
    let mut result = 1i64;
    let mut b = base % Q as i64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b) % Q as i64;
        }
        b = (b * b) % Q as i64;
        exp >>= 1;
    }
    result
}

// ZETAS[i] = 1753^{brv8(i)} mod Q, the twiddle factors used by the transform (FIPS 204, section 7.5).
const ZETAS: [i32; N] = {
    let mut z = [0i32; N];
    let mut i = 0;
    while i < N {
        z[i] = pow_mod(1753, brv8(i)) as i32;
        i += 1;
    }
    z
};

// In-place forward NTT (FIPS 204, Algorithm 41). Coefficients stay in [0, Q).
fn ntt(a: &mut Poly) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            let mut j = start;
            while j < start + len {
                let t = mul_q(zeta, a[j + len]);
                a[j + len] = sub_q(a[j], t);
                a[j] = add_q(a[j], t);
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

// In-place inverse NTT (FIPS 204, Algorithm 42). Coefficients stay in [0, Q).
fn inv_ntt(a: &mut Poly) {
    // 256^{-1} mod Q.
    const F: i32 = 8347681;
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = Q - ZETAS[k];
            let mut j = start;
            while j < start + len {
                let t = a[j];
                a[j] = add_q(t, a[j + len]);
                a[j + len] = sub_q(t, a[j + len]);
                a[j + len] = mul_q(zeta, a[j + len]);
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for x in a.iter_mut() {
        *x = mul_q(F, *x);
    }
}

// Pointwise product in the NTT domain, accumulated into acc.
fn pointwise_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc[i] = add_q(acc[i], mul_q(a[i], b[i]));
    }
}

// Bit packing (FIPS 204, section 7.1). Coefficients are packed least significant bit first.

fn pack_bits(coeffs: &Poly, bits: usize, out: &mut Vec<u8>) {
    let mask: u64 = (1u64 << bits) - 1;
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    for &c in coeffs.iter() {
        acc |= (c as u64 & mask) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out.push((acc & 0xff) as u8);
            acc >>= 8;
            acc_bits -= 8;
        }
    }
}

fn unpack_bits(data: &[u8], bits: usize) -> Poly {
    let mask: u64 = (1u64 << bits) - 1;
    let mut coeffs = ZERO_POLY;
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    let mut byte = 0usize;
    for c in coeffs.iter_mut() {
        while acc_bits < bits {
            acc |= (data[byte] as u64) << acc_bits;
            byte += 1;
            acc_bits += 8;
        }
        *c = (acc & mask) as i32;
        acc >>= bits;
        acc_bits -= bits;
    }
    coeffs
}

// Rounding helpers (FIPS 204, section 7.4).

// Power2Round: split r in [0, Q) into (r1, r0) with r = r1 * 2^D + r0 and r0 in (-2^{D-1}, 2^{D-1}].
fn power2round(r: i32) -> (i32, i32) {
    let mut r0 = r & ((1 << D) - 1);
    if r0 > (1 << (D - 1)) {
        r0 -= 1 << D;
    }
    let r1 = (r - r0) >> D;
    (r1, r0)
}

// Decompose r in [0, Q) into (r1, r0) using 2*GAMMA2 as the modulus (FIPS 204, Algorithm 36).
fn decompose(r: i32) -> (i32, i32) {
    let mut r0 = r % (2 * GAMMA2);
    if r0 > GAMMA2 {
        r0 -= 2 * GAMMA2;
    }
    if r - r0 == Q - 1 {
        return (0, r0 - 1);
    }
    let r1 = (r - r0) / (2 * GAMMA2);
    (r1, r0)
}

fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

// MakeHint (FIPS 204, Algorithm 39): does adding z to r change the high bits.
fn make_hint(z: i32, r: i32) -> u8 {
    if high_bits(r) != high_bits(add_q(r, z)) {
        1
    } else {
        0
    }
}

// UseHint (FIPS 204, Algorithm 40): recover the high bits given the hint bit.
fn use_hint(h: u8, r: i32) -> i32 {
    let m = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose(r);
    if h == 0 {
        r1
    } else if r0 > 0 {
        (r1 + 1).rem_euclid(m)
    } else {
        (r1 - 1).rem_euclid(m)
    }
}
