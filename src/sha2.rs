// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::zeroize::Zeroize;

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const IV512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const IV384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

const BLOCK: usize = 128;

fn compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for t in 0..16 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[t * 8..t * 8 + 8]);
        w[t] = u64::from_be_bytes(b);
    }
    for t in 16..80 {
        let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
        let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for t in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
    w[..].zeroize();
}

pub struct Sha512Core {
    state: [u64; 8],
    buf: [u8; BLOCK],
    used: usize,
    total: u128,
}

impl Clone for Sha512Core {
    fn clone(&self) -> Self {
        Sha512Core {
            state: self.state,
            buf: self.buf,
            used: self.used,
            total: self.total,
        }
    }
}

impl Drop for Sha512Core {
    fn drop(&mut self) {
        self.state[..].zeroize();
        self.buf[..].zeroize();
    }
}

impl Sha512Core {
    fn with_iv(iv: [u64; 8]) -> Self {
        Sha512Core {
            state: iv,
            buf: [0u8; BLOCK],
            used: 0,
            total: 0,
        }
    }

    pub fn new_512() -> Self {
        Self::with_iv(IV512)
    }

    pub fn new_384() -> Self {
        Self::with_iv(IV384)
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add((data.len() as u128) * 8);
        if self.used > 0 {
            let take = core::cmp::min(BLOCK - self.used, data.len());
            self.buf[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == BLOCK {
                let mut block = self.buf;
                compress(&mut self.state, &block);
                block[..].zeroize();
                self.used = 0;
            }
        }
        while data.len() >= BLOCK {
            compress(&mut self.state, &data[..BLOCK]);
            data = &data[BLOCK..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.used = data.len();
        }
    }

    fn finish(mut self) -> [u8; 64] {
        let bits = self.total;
        let mut pad = [0u8; 2 * BLOCK];
        pad[0] = 0x80;
        let padlen = if self.used < 112 {
            112 - self.used
        } else {
            240 - self.used
        };
        let mut tail = Vec::with_capacity(padlen + 16);
        tail.extend_from_slice(&pad[..padlen]);
        tail.extend_from_slice(&bits.to_be_bytes());
        let total = self.total;
        self.update(&tail);
        self.total = total;
        debug_assert_eq!(self.used, 0);
        let mut out = [0u8; 64];
        for (i, v) in self.state.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&v.to_be_bytes());
        }
        tail[..].zeroize();
        out
    }

    pub fn finalize_512(self) -> [u8; 64] {
        self.finish()
    }

    pub fn finalize_384(self) -> [u8; 48] {
        let full = self.finish();
        let mut out = [0u8; 48];
        out.copy_from_slice(&full[..48]);
        out
    }
}

pub fn sha512(input: &[u8]) -> [u8; 64] {
    let mut h = Sha512Core::new_512();
    h.update(input);
    h.finalize_512()
}

pub fn sha384(input: &[u8]) -> [u8; 48] {
    let mut h = Sha512Core::new_384();
    h.update(input);
    h.finalize_384()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn hex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn records(name: &str) -> Vec<Vec<String>> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("vectors/sha2");
        path.push(name);
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.split_whitespace().map(|s| s.to_string()).collect())
            .collect()
    }

    #[test]
    fn sha512_known_answers() {
        assert_eq!(
            sha512(b"abc")[..],
            hex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )[..]
        );
    }

    #[test]
    fn sha384_known_answers() {
        assert_eq!(
            sha384(b"abc")[..],
            hex(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7"
            )[..]
        );
    }

    #[test]
    fn sha512_matches_official_vectors() {
        let recs = records("sha512.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            assert_eq!(sha512(&hex(&r[0]))[..], hex(&r[1])[..]);
        }
    }

    #[test]
    fn sha384_matches_official_vectors() {
        let recs = records("sha384.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            assert_eq!(sha384(&hex(&r[0]))[..], hex(&r[1])[..]);
        }
    }

    #[test]
    fn streaming_matches_one_shot_at_every_split() {
        let data: Vec<u8> = (0..700u32).map(|i| (i * 31 + 7) as u8).collect();
        let want = sha512(&data);
        for split in [0usize, 1, 111, 112, 127, 128, 129, 255, 256, 699, 700] {
            let mut h = Sha512Core::new_512();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize_512(), want);
        }
        for len in 0..300usize {
            let mut h = Sha512Core::new_384();
            for b in &data[..len] {
                h.update(core::slice::from_ref(b));
            }
            assert_eq!(h.finalize_384(), sha384(&data[..len]));
        }
    }
}
