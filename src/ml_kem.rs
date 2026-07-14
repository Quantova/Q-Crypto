//! ML-KEM (FIPS 203) - module lattice key encapsulation. Backs the QUIC transport key exchange in

// The key generation, encapsulation, and decapsulation routines that consume this arithmetic land
// in the following piece, so the helpers below have no callers yet.
#![allow(dead_code)]

// Parameters for ML-KEM-768 (FIPS 203, Table 2).
const Q: i32 = 3329; // prime modulus, 13 * 2^8 + 1
const N: usize = 256; // ring degree
const K: usize = 3; // module rank
const ETA1: usize = 2; // secret and error CBD parameter
const ETA2: usize = 2; // encryption error CBD parameter
const DU: usize = 10; // ciphertext compression bits for u
const DV: usize = 4; // ciphertext compression bits for v

// Number of bytes in ByteEncode_12 of a single ring element (12 bits per coefficient).
const POLY_BYTES: usize = 12 * N / 8; // 384

/// Encoded ML-KEM-768 encapsulation key length in bytes.
pub const ENCAPS_KEY_BYTES: usize = K * POLY_BYTES + 32; // 1184
/// Encoded ML-KEM-768 decapsulation key length in bytes.
pub const DECAPS_KEY_BYTES: usize = 2 * K * POLY_BYTES + 96; // 2400
/// Encoded ML-KEM-768 ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = 32 * (DU * K + DV); // 1088
/// Length of the shared secret in bytes.
pub const SHARED_SECRET_BYTES: usize = 32;
/// Length of each key generation and encapsulation seed in bytes.
pub const SEED_BYTES: usize = 32;

/// Encoded ML-KEM-768 encapsulation key.
pub type EncapsKey = [u8; ENCAPS_KEY_BYTES];
/// Encoded ML-KEM-768 decapsulation key.
pub type DecapsKey = [u8; DECAPS_KEY_BYTES];
/// Encoded ML-KEM-768 ciphertext.
pub type Ciphertext = [u8; CIPHERTEXT_BYTES];
/// The shared secret produced by encapsulation and decapsulation.
pub type SharedSecret = [u8; SHARED_SECRET_BYTES];

// A ring element, represented by its 256 coefficients in [0, Q).
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
    (a * b) % Q
}

// Number theoretic transform tables.

// Bit reversal of the low seven bits of i.
const fn brv7(mut i: usize) -> u32 {
    let mut r = 0u32;
    let mut b = 0;
    while b < 7 {
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

// ZETAS[i] = 17^{brv7(i)} mod Q, the twiddle factors of the length-128 transform (FIPS 203, 4.3).
const ZETAS: [i32; 128] = {
    let mut z = [0i32; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = pow_mod(17, brv7(i)) as i32;
        i += 1;
    }
    z
};

// GAMMAS[i] = 17^{2*brv7(i)+1} mod Q, the moduli of the degree-two base rings (FIPS 203, 4.3).
const GAMMAS: [i32; 128] = {
    let mut g = [0i32; 128];
    let mut i = 0;
    while i < 128 {
        g[i] = pow_mod(17, 2 * brv7(i) + 1) as i32;
        i += 1;
    }
    g
};

// In-place forward NTT (FIPS 203, Algorithm 9). Coefficients stay in [0, Q).
fn ntt(a: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
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

// In-place inverse NTT (FIPS 203, Algorithm 10). Coefficients stay in [0, Q).
fn inv_ntt(a: &mut Poly) {
    // 128^{-1} mod Q.
    const F: i32 = 3303;
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            let mut j = start;
            while j < start + len {
                let t = a[j];
                let u = a[j + len];
                a[j] = add_q(t, u);
                a[j + len] = mul_q(zeta, sub_q(u, t));
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

// MultiplyNTTs (FIPS 203, Algorithm 11) built from BaseCaseMultiply (Algorithm 12). The product of
// two NTT-domain elements is taken in the 128 degree-two rings Z_q[x]/(x^2 - GAMMAS[i]).
fn multiply_ntts(f: &Poly, g: &Poly) -> Poly {
    let mut h = ZERO_POLY;
    let mut i = 0usize;
    while i < 128 {
        let gamma = GAMMAS[i];
        let a0 = f[2 * i];
        let a1 = f[2 * i + 1];
        let b0 = g[2 * i];
        let b1 = g[2 * i + 1];
        h[2 * i] = add_q(mul_q(a0, b0), mul_q(mul_q(a1, b1), gamma));
        h[2 * i + 1] = add_q(mul_q(a0, b1), mul_q(a1, b0));
        i += 1;
    }
    h
}

// Pointwise product in the NTT domain, accumulated into acc.
fn pointwise_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    let h = multiply_ntts(a, b);
    for i in 0..N {
        acc[i] = add_q(acc[i], h[i]);
    }
}

// Compression and decompression (FIPS 203, 4.2.1). Coefficients round to and from d-bit values.

fn compress(x: i32, d: usize) -> i32 {
    let t = ((x as u32) << d) + (Q as u32) / 2;
    ((t / Q as u32) & ((1u32 << d) - 1)) as i32
}

fn decompress(y: i32, d: usize) -> i32 {
    let t = (y as u32 * Q as u32 + (1u32 << (d - 1))) >> d;
    t as i32
}

// Bit packing (FIPS 203, ByteEncode and ByteDecode, Algorithms 5 and 6). Coefficients are packed
// least significant bit first.

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

// ByteDecode_12 of one ring element, reducing each coefficient modulo Q (FIPS 203, Algorithm 6).
fn byte_decode_12(data: &[u8]) -> Poly {
    let mut p = unpack_bits(data, 12);
    for c in p.iter_mut() {
        *c %= Q;
    }
    p
}
