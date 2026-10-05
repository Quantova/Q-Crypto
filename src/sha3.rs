// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::zeroize::Zeroize;

const RC: [u64; 24] = [
    1,
    32898,
    9223372036854808714,
    9223372039002292224,
    32907,
    2147483649,
    9223372039002292353,
    9223372036854808585,
    138,
    136,
    2147516425,
    2147483658,
    2147516555,
    9223372036854775947,
    9223372036854808713,
    9223372036854808579,
    9223372036854808578,
    9223372036854775936,
    32778,
    9223372039002259466,
    9223372039002292353,
    9223372036854808704,
    2147483649,
    9223372039002292232,
];

fn qudros_f1600(a: &mut [u64; 25]) {
    for rc in RC {
        let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        let d0 = c4 ^ c1.rotate_left(1);
        let d1 = c0 ^ c2.rotate_left(1);
        let d2 = c1 ^ c3.rotate_left(1);
        let d3 = c2 ^ c4.rotate_left(1);
        let d4 = c3 ^ c0.rotate_left(1);
        let b0 = a[0] ^ d0;
        let b1 = (a[6] ^ d1).rotate_left(44);
        let b2 = (a[12] ^ d2).rotate_left(43);
        let b3 = (a[18] ^ d3).rotate_left(21);
        let b4 = (a[24] ^ d4).rotate_left(14);
        let b5 = (a[3] ^ d3).rotate_left(28);
        let b6 = (a[9] ^ d4).rotate_left(20);
        let b7 = (a[10] ^ d0).rotate_left(3);
        let b8 = (a[16] ^ d1).rotate_left(45);
        let b9 = (a[22] ^ d2).rotate_left(61);
        let b10 = (a[1] ^ d1).rotate_left(1);
        let b11 = (a[7] ^ d2).rotate_left(6);
        let b12 = (a[13] ^ d3).rotate_left(25);
        let b13 = (a[19] ^ d4).rotate_left(8);
        let b14 = (a[20] ^ d0).rotate_left(18);
        let b15 = (a[4] ^ d4).rotate_left(27);
        let b16 = (a[5] ^ d0).rotate_left(36);
        let b17 = (a[11] ^ d1).rotate_left(10);
        let b18 = (a[17] ^ d2).rotate_left(15);
        let b19 = (a[23] ^ d3).rotate_left(56);
        let b20 = (a[2] ^ d2).rotate_left(62);
        let b21 = (a[8] ^ d3).rotate_left(55);
        let b22 = (a[14] ^ d4).rotate_left(39);
        let b23 = (a[15] ^ d0).rotate_left(41);
        let b24 = (a[21] ^ d1).rotate_left(2);
        a[0] = b0 ^ (!b1 & b2);
        a[1] = b1 ^ (!b2 & b3);
        a[2] = b2 ^ (!b3 & b4);
        a[3] = b3 ^ (!b4 & b0);
        a[4] = b4 ^ (!b0 & b1);
        a[5] = b5 ^ (!b6 & b7);
        a[6] = b6 ^ (!b7 & b8);
        a[7] = b7 ^ (!b8 & b9);
        a[8] = b8 ^ (!b9 & b5);
        a[9] = b9 ^ (!b5 & b6);
        a[10] = b10 ^ (!b11 & b12);
        a[11] = b11 ^ (!b12 & b13);
        a[12] = b12 ^ (!b13 & b14);
        a[13] = b13 ^ (!b14 & b10);
        a[14] = b14 ^ (!b10 & b11);
        a[15] = b15 ^ (!b16 & b17);
        a[16] = b16 ^ (!b17 & b18);
        a[17] = b17 ^ (!b18 & b19);
        a[18] = b18 ^ (!b19 & b15);
        a[19] = b19 ^ (!b15 & b16);
        a[20] = b20 ^ (!b21 & b22);
        a[21] = b21 ^ (!b22 & b23);
        a[22] = b22 ^ (!b23 & b24);
        a[23] = b23 ^ (!b24 & b20);
        a[24] = b24 ^ (!b20 & b21);
        a[0] ^= rc;
    }
}

fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for (lane, bytes) in state.iter_mut().zip(block.chunks_exact(8)) {
        let mut word = [0u8; 8];
        word.copy_from_slice(bytes);
        *lane ^= u64::from_le_bytes(word);
    }
}

fn squeeze_block(state: &[u64; 25], out: &mut [u8]) {
    for (bytes, lane) in out.chunks_mut(8).zip(state.iter()) {
        let word = lane.to_le_bytes();
        bytes.copy_from_slice(&word[..bytes.len()]);
    }
}

fn sponge(rate: usize, domain: u8, input: &[u8], output: &mut [u8]) {
    let mut state = [0u64; 25];

    let mut blocks = input.chunks_exact(rate);
    for block in &mut blocks {
        absorb_block(&mut state, block);
        qudros_f1600(&mut state);
    }

    let tail = blocks.remainder();
    let mut last = [0u8; 200];
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] ^= domain;
    last[rate - 1] ^= 128;
    absorb_block(&mut state, &last[..rate]);
    last.zeroize();
    qudros_f1600(&mut state);

    let mut chunks = output.chunks_mut(rate);
    if let Some(first) = chunks.next() {
        squeeze_block(&state, first);
    }
    for chunk in chunks {
        qudros_f1600(&mut state);
        squeeze_block(&state, chunk);
    }
    state[..].zeroize();
}

pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sponge(136, 6, input, &mut out);
    out
}

pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    sponge(72, 6, input, &mut out);
    out
}

pub fn shake128(input: &[u8], output: &mut [u8]) {
    sponge(168, 31, input, output);
}

pub fn shake256(input: &[u8], output: &mut [u8]) {
    sponge(136, 31, input, output);
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
        path.push("vectors/sha3");
        path.push(name);
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.split_whitespace().map(|s| s.to_string()).collect())
            .collect()
    }

    #[test]
    fn sha3_256_known_answers() {
        assert_eq!(
            sha3_256(b"")[..],
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")[..]
        );
        assert_eq!(
            sha3_256(b"abc")[..],
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")[..]
        );
    }

    #[test]
    fn sha3_512_known_answers() {
        assert_eq!(
            sha3_512(b"")[..],
            hex(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
                 15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )[..]
        );
        assert_eq!(
            sha3_512(b"abc")[..],
            hex(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )[..]
        );
    }

    #[test]
    fn shake128_known_answers() {
        let mut empty = [0u8; 32];
        shake128(b"", &mut empty);
        assert_eq!(
            empty[..],
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")[..]
        );

        let mut abc = [0u8; 32];
        shake128(b"abc", &mut abc);
        assert_eq!(
            abc[..],
            hex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")[..]
        );
    }

    #[test]
    fn shake256_known_answers() {
        let mut empty = [0u8; 32];
        shake256(b"", &mut empty);
        assert_eq!(
            empty[..],
            hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")[..]
        );

        let mut abc = [0u8; 32];
        shake256(b"abc", &mut abc);
        assert_eq!(
            abc[..],
            hex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")[..]
        );
    }

    #[test]
    fn sha3_256_differs_from_classical() {
        let fips = sha3_256(b"");
        assert_eq!(
            fips[..],
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")[..]
        );
        assert_ne!(
            fips[..],
            hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")[..]
        );
    }

    #[test]
    fn sha3_256_matches_cavp_vectors() {
        let recs = records("sha3_256.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let msg = hex(&r[0]);
            let want = hex(&r[1]);
            assert_eq!(&sha3_256(&msg)[..], &want[..], "SHA3-256 mismatch");
        }
    }

    #[test]
    fn sha3_512_matches_cavp_vectors() {
        let recs = records("sha3_512.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let msg = hex(&r[0]);
            let want = hex(&r[1]);
            assert_eq!(&sha3_512(&msg)[..], &want[..], "SHA3-512 mismatch");
        }
    }

    #[test]
    fn shake128_matches_cavp_vectors() {
        let recs = records("shake128.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let msg = hex(&r[0]);
            let outlen: usize = r[1].parse().unwrap();
            let want = hex(&r[2]);
            let mut out = vec![0u8; outlen];
            shake128(&msg, &mut out);
            assert_eq!(out, want, "SHAKE128 mismatch");
        }
    }

    #[test]
    fn shake256_matches_cavp_vectors() {
        let recs = records("shake256.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let msg = hex(&r[0]);
            let outlen: usize = r[1].parse().unwrap();
            let want = hex(&r[2]);
            let mut out = vec![0u8; outlen];
            shake256(&msg, &mut out);
            assert_eq!(out, want, "SHAKE256 mismatch");
        }
    }
}
