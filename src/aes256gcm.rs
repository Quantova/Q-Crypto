// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::zeroize::{Zeroize, Zeroizing};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;

const ROUNDS: usize = 14;
const BLOCK: usize = 16;

pub const MAX_AEAD_PLAINTEXT: usize = if usize::BITS >= 64 {
    (((1u64 << 32) - 2) * 16) as usize
} else {
    usize::MAX
};

fn exceeds_aead_bound(len: usize) -> bool {
    len as u64 > ((1u64 << 32) - 2) * 16
}

fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut product = 0u8;
    for _ in 0..8 {
        product ^= a & 0u8.wrapping_sub(b & 1);
        let carry = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & carry);
        b >>= 1;
    }
    product
}

fn sbox(x: u8) -> u8 {
    let x2 = gf_mul(x, x);
    let x3 = gf_mul(x2, x);
    let x6 = gf_mul(x3, x3);
    let x12 = gf_mul(x6, x6);
    let x15 = gf_mul(x12, x3);
    let x30 = gf_mul(x15, x15);
    let x60 = gf_mul(x30, x30);
    let x120 = gf_mul(x60, x60);
    let x126 = gf_mul(x120, x6);
    let x127 = gf_mul(x126, x);
    let inverse = gf_mul(x127, x127);
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

fn xtime(a: u8) -> u8 {
    (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7))
}

struct Schedule {
    keys: [[u8; BLOCK]; ROUNDS + 1],
}

impl Drop for Schedule {
    fn drop(&mut self) {
        for k in self.keys.iter_mut() {
            k.zeroize();
        }
    }
}

impl Schedule {
    fn new(key: &[u8; KEY_BYTES]) -> Schedule {
        let mut words = [[0u8; 4]; 4 * (ROUNDS + 1)];
        for (i, w) in words.iter_mut().take(8).enumerate() {
            w.copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in 8..4 * (ROUNDS + 1) {
            let mut t = words[i - 1];
            if i % 8 == 0 {
                t = [sbox(t[1]) ^ rcon, sbox(t[2]), sbox(t[3]), sbox(t[0])];
                rcon = xtime(rcon);
            } else if i % 8 == 4 {
                t = [sbox(t[0]), sbox(t[1]), sbox(t[2]), sbox(t[3])];
            }
            for j in 0..4 {
                words[i][j] = words[i - 8][j] ^ t[j];
            }
        }
        let mut keys = [[0u8; BLOCK]; ROUNDS + 1];
        for (r, k) in keys.iter_mut().enumerate() {
            for c in 0..4 {
                k[4 * c..4 * c + 4].copy_from_slice(&words[4 * r + c]);
            }
        }
        for w in words.iter_mut() {
            w.zeroize();
        }
        Schedule { keys }
    }

    fn encrypt(&self, block: &mut [u8; BLOCK]) {
        add_round_key(block, &self.keys[0]);
        for round in 1..=ROUNDS {
            for b in block.iter_mut() {
                *b = sbox(*b);
            }
            shift_rows(block);
            if round != ROUNDS {
                mix_columns(block);
            }
            add_round_key(block, &self.keys[round]);
        }
    }
}

fn add_round_key(block: &mut [u8; BLOCK], key: &[u8; BLOCK]) {
    for (b, k) in block.iter_mut().zip(key.iter()) {
        *b ^= k;
    }
}

fn shift_rows(s: &mut [u8; BLOCK]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[4 * c + r] = t[4 * ((c + r) % 4) + r];
        }
    }
}

fn mix_columns(s: &mut [u8; BLOCK]) {
    for c in 0..4 {
        let a = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
        let all = a[0] ^ a[1] ^ a[2] ^ a[3];
        for r in 0..4 {
            s[4 * c + r] = a[r] ^ all ^ xtime(a[r] ^ a[(r + 1) % 4]);
        }
    }
}

fn gf128_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        z ^= v & 0u128.wrapping_sub(bit);
        let low = v & 1;
        v >>= 1;
        v ^= (0xe1u128 << 120) & 0u128.wrapping_sub(low);
    }
    z
}

fn ghash(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut y = 0u128;
    for data in [aad, ciphertext] {
        for chunk in data.chunks(BLOCK) {
            let mut block = [0u8; BLOCK];
            block[..chunk.len()].copy_from_slice(chunk);
            y = gf128_mul(y ^ u128::from_be_bytes(block), h);
        }
    }
    let lengths = ((aad.len() as u128 * 8) << 64) | (ciphertext.len() as u128 * 8);
    gf128_mul(y ^ lengths, h)
}

fn counter_block(nonce: &[u8; NONCE_BYTES], counter: u32) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    block[..NONCE_BYTES].copy_from_slice(nonce);
    block[NONCE_BYTES..].copy_from_slice(&counter.to_be_bytes());
    block
}

fn ctr(schedule: &Schedule, nonce: &[u8; NONCE_BYTES], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(BLOCK).enumerate() {
        let mut stream = Zeroizing::new(counter_block(nonce, (i as u32).wrapping_add(2)));
        schedule.encrypt(&mut stream);
        for (d, s) in chunk.iter_mut().zip(stream.iter()) {
            *d ^= s;
        }
    }
}

fn tag_for(
    schedule: &Schedule,
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; TAG_BYTES] {
    let mut h_block = Zeroizing::new([0u8; BLOCK]);
    schedule.encrypt(&mut h_block);
    let mut h = u128::from_be_bytes(*h_block);
    let s = ghash(h, aad, ciphertext);
    h = 0;
    core::hint::black_box(h);
    let mut j0 = Zeroizing::new(counter_block(nonce, 1));
    schedule.encrypt(&mut j0);
    (u128::from_be_bytes(*j0) ^ s).to_be_bytes()
}

fn constant_time_eq(a: &[u8; TAG_BYTES], b: &[u8; TAG_BYTES]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

pub fn seal(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Option<(Vec<u8>, [u8; TAG_BYTES])> {
    if exceeds_aead_bound(plaintext.len()) {
        return None;
    }
    let schedule = Schedule::new(key);
    let mut ciphertext = plaintext.to_vec();
    ctr(&schedule, nonce, &mut ciphertext);
    let tag = tag_for(&schedule, nonce, aad, &ciphertext);
    Some((ciphertext, tag))
}

pub fn open(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) -> Option<Vec<u8>> {
    if exceeds_aead_bound(ciphertext.len()) {
        return None;
    }
    let schedule = Schedule::new(key);
    let expected = tag_for(&schedule, nonce, aad, ciphertext);
    if !constant_time_eq(&expected, tag) {
        return None;
    }
    let mut plaintext = ciphertext.to_vec();
    ctr(&schedule, nonce, &mut plaintext);
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn check(key: &str, nonce: &str, aad: &str, plaintext: &str, ciphertext: &str, tag: &str) {
        let key: [u8; KEY_BYTES] = hex(key).try_into().unwrap();
        let nonce: [u8; NONCE_BYTES] = hex(nonce).try_into().unwrap();
        let (ct, t) = seal(&key, &nonce, &hex(aad), &hex(plaintext)).unwrap();
        assert_eq!(ct, hex(ciphertext));
        assert_eq!(t.to_vec(), hex(tag));
        assert_eq!(
            open(&key, &nonce, &hex(aad), &ct, &t).unwrap(),
            hex(plaintext)
        );
        let mut bad = t;
        bad[0] ^= 1;
        assert!(open(&key, &nonce, &hex(aad), &ct, &bad).is_none());
    }

    #[test]
    fn the_sbox_matches_the_standard_table_corners() {
        assert_eq!(sbox(0x00), 0x63);
        assert_eq!(sbox(0x01), 0x7c);
        assert_eq!(sbox(0x53), 0xed);
        assert_eq!(sbox(0xff), 0x16);
    }

    #[test]
    fn the_fips_197_aes_256_block_vector() {
        let key: [u8; KEY_BYTES] =
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .try_into()
                .unwrap();
        let mut block: [u8; BLOCK] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        Schedule::new(&key).encrypt(&mut block);
        assert_eq!(block.to_vec(), hex("8ea2b7ca516745bfeafc49904b496089"));
    }

    #[test]
    fn gcm_test_case_13() {
        check(
            &"00".repeat(32),
            &"00".repeat(12),
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        );
    }

    #[test]
    fn gcm_test_case_14() {
        check(
            &"00".repeat(32),
            &"00".repeat(12),
            "",
            &"00".repeat(16),
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        );
    }

    #[test]
    fn gcm_test_case_15() {
        check(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        );
    }

    #[test]
    fn gcm_test_case_16() {
        check(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        );
    }
}
