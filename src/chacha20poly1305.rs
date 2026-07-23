use crate::zeroize::Zeroizing;

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;

const CONSTANTS: [u32; 4] = [1634760805, 857760878, 2036477234, 1797285236];

fn load_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; KEY_BYTES], counter: u32, nonce: &[u8; NONCE_BYTES]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[0..4].copy_from_slice(&CONSTANTS);
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        init[4 + i] = load_u32(chunk);
    }
    init[12] = counter;
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        init[13 + i] = load_u32(chunk);
    }

    let mut state = init;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, (word, base)) in state.iter().zip(init.iter()).enumerate() {
        let sum = word.wrapping_add(*base);
        out[4 * i..4 * i + 4].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

pub fn chacha20(key: &[u8; KEY_BYTES], counter: u32, nonce: &[u8; NONCE_BYTES], data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                chacha20_avx2(key, counter, nonce, data);
            }
            return;
        }
    }

    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let block = chacha20_block(key, counter.wrapping_add(i as u32), nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn chacha20_avx2(
    key: &[u8; KEY_BYTES],
    counter: u32,
    nonce: &[u8; NONCE_BYTES],
    data: &mut [u8],
) {
    let mut blk = counter;
    let mut chunks = data.chunks_exact_mut(512);
    for chunk in chunks.by_ref() {
        let keystream = unsafe { chacha20_8block(key, blk, nonce) };
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
            *b ^= *k;
        }
        blk = blk.wrapping_add(8);
    }
    for (i, chunk) in chunks.into_remainder().chunks_mut(64).enumerate() {
        let block = chacha20_block(key, blk.wrapping_add(i as u32), nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn chacha20_8block(
    key: &[u8; KEY_BYTES],
    counter: u32,
    nonce: &[u8; NONCE_BYTES],
) -> [u8; 512] {
    use core::arch::x86_64::*;

    unsafe {
        let mut init = [_mm256_setzero_si256(); 16];
        init[0] = _mm256_set1_epi32(CONSTANTS[0] as i32);
        init[1] = _mm256_set1_epi32(CONSTANTS[1] as i32);
        init[2] = _mm256_set1_epi32(CONSTANTS[2] as i32);
        init[3] = _mm256_set1_epi32(CONSTANTS[3] as i32);
        for i in 0..8 {
            init[4 + i] = _mm256_set1_epi32(load_u32(&key[4 * i..]) as i32);
        }
        init[12] = _mm256_add_epi32(
            _mm256_set1_epi32(counter as i32),
            _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0),
        );
        init[13] = _mm256_set1_epi32(load_u32(&nonce[0..]) as i32);
        init[14] = _mm256_set1_epi32(load_u32(&nonce[4..]) as i32);
        init[15] = _mm256_set1_epi32(load_u32(&nonce[8..]) as i32);

        let rot16 = _mm256_set_epi8(
            13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5,
            4, 7, 6, 1, 0, 3, 2,
        );
        let rot8 = _mm256_set_epi8(
            14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6,
            5, 4, 7, 2, 1, 0, 3,
        );

        let mut x0 = init[0];
        let mut x1 = init[1];
        let mut x2 = init[2];
        let mut x3 = init[3];
        let mut x4 = init[4];
        let mut x5 = init[5];
        let mut x6 = init[6];
        let mut x7 = init[7];
        let mut x8 = init[8];
        let mut x9 = init[9];
        let mut x10 = init[10];
        let mut x11 = init[11];
        let mut x12 = init[12];
        let mut x13 = init[13];
        let mut x14 = init[14];
        let mut x15 = init[15];

        macro_rules! qr {
            ($a:ident, $b:ident, $c:ident, $d:ident) => {{
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_shuffle_epi8(_mm256_xor_si256($d, $a), rot16);
                $c = _mm256_add_epi32($c, $d);
                let t12 = _mm256_xor_si256($b, $c);
                $b = _mm256_or_si256(_mm256_slli_epi32(t12, 12), _mm256_srli_epi32(t12, 20));
                $a = _mm256_add_epi32($a, $b);
                $d = _mm256_shuffle_epi8(_mm256_xor_si256($d, $a), rot8);
                $c = _mm256_add_epi32($c, $d);
                let t7 = _mm256_xor_si256($b, $c);
                $b = _mm256_or_si256(_mm256_slli_epi32(t7, 7), _mm256_srli_epi32(t7, 25));
            }};
        }

        for _ in 0..10 {
            qr!(x0, x4, x8, x12);
            qr!(x1, x5, x9, x13);
            qr!(x2, x6, x10, x14);
            qr!(x3, x7, x11, x15);
            qr!(x0, x5, x10, x15);
            qr!(x1, x6, x11, x12);
            qr!(x2, x7, x8, x13);
            qr!(x3, x4, x9, x14);
        }

        x0 = _mm256_add_epi32(x0, init[0]);
        x1 = _mm256_add_epi32(x1, init[1]);
        x2 = _mm256_add_epi32(x2, init[2]);
        x3 = _mm256_add_epi32(x3, init[3]);
        x4 = _mm256_add_epi32(x4, init[4]);
        x5 = _mm256_add_epi32(x5, init[5]);
        x6 = _mm256_add_epi32(x6, init[6]);
        x7 = _mm256_add_epi32(x7, init[7]);
        x8 = _mm256_add_epi32(x8, init[8]);
        x9 = _mm256_add_epi32(x9, init[9]);
        x10 = _mm256_add_epi32(x10, init[10]);
        x11 = _mm256_add_epi32(x11, init[11]);
        x12 = _mm256_add_epi32(x12, init[12]);
        x13 = _mm256_add_epi32(x13, init[13]);
        x14 = _mm256_add_epi32(x14, init[14]);
        x15 = _mm256_add_epi32(x15, init[15]);

        let state = [
            x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
        ];
        let mut words = [[0u32; 8]; 16];
        for k in 0..16 {
            _mm256_storeu_si256(words[k].as_mut_ptr() as *mut __m256i, state[k]);
        }
        let mut out = [0u8; 512];
        for blk in 0..8 {
            for k in 0..16 {
                let off = blk * 64 + k * 4;
                out[off..off + 4].copy_from_slice(&words[k][blk].to_le_bytes());
            }
        }
        out
    }
}

fn poly1305_block(h: &mut [u64; 5], block: &[u8], hibit: u64, r: &[u64; 5], s: &[u64; 4]) {
    let t0 = load_u32(&block[0..]) as u64;
    let t1 = load_u32(&block[4..]) as u64;
    let t2 = load_u32(&block[8..]) as u64;
    let t3 = load_u32(&block[12..]) as u64;

    h[0] += t0 & 67108863;
    h[1] += ((t0 >> 26) | (t1 << 6)) & 67108863;
    h[2] += ((t1 >> 20) | (t2 << 12)) & 67108863;
    h[3] += ((t2 >> 14) | (t3 << 18)) & 67108863;
    h[4] += (t3 >> 8) | hibit;

    let d0 = h[0] * r[0] + h[1] * s[3] + h[2] * s[2] + h[3] * s[1] + h[4] * s[0];
    let d1 = h[0] * r[1] + h[1] * r[0] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1];
    let d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[3] + h[4] * s[2];
    let d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[3];
    let d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];

    let mut c = d0 >> 26;
    h[0] = d0 & 67108863;
    let d1 = d1 + c;
    c = d1 >> 26;
    h[1] = d1 & 67108863;
    let d2 = d2 + c;
    c = d2 >> 26;
    h[2] = d2 & 67108863;
    let d3 = d3 + c;
    c = d3 >> 26;
    h[3] = d3 & 67108863;
    let d4 = d4 + c;
    c = d4 >> 26;
    h[4] = d4 & 67108863;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 67108863;
    h[1] += c;
}

pub fn poly1305(key: &[u8; 32], message: &[u8]) -> [u8; TAG_BYTES] {
    let r0 = (load_u32(&key[0..]) & 67108863) as u64;
    let r1 = ((load_u32(&key[3..]) >> 2) & 67108611) as u64;
    let r2 = ((load_u32(&key[6..]) >> 4) & 67092735) as u64;
    let r3 = ((load_u32(&key[9..]) >> 6) & 66076671) as u64;
    let r4 = ((load_u32(&key[12..]) >> 8) & 1048575) as u64;
    let r = [r0, r1, r2, r3, r4];
    let s = [r1 * 5, r2 * 5, r3 * 5, r4 * 5];

    let mut h = [0u64; 5];
    let mut blocks = message.chunks_exact(16);
    for block in blocks.by_ref() {
        poly1305_block(&mut h, block, 1 << 24, &r, &s);
    }
    let rem = blocks.remainder();
    if !rem.is_empty() {
        let mut last = [0u8; 16];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 1;
        poly1305_block(&mut h, &last, 0, &r, &s);
    }

    let mut c = h[1] >> 26;
    h[1] &= 67108863;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 67108863;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 67108863;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 67108863;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 67108863;
    h[1] += c;

    let mut g = [0u64; 5];
    g[0] = h[0] + 5;
    c = g[0] >> 26;
    g[0] &= 67108863;
    g[1] = h[1] + c;
    c = g[1] >> 26;
    g[1] &= 67108863;
    g[2] = h[2] + c;
    c = g[2] >> 26;
    g[2] &= 67108863;
    g[3] = h[3] + c;
    c = g[3] >> 26;
    g[3] &= 67108863;
    g[4] = (h[4] + c).wrapping_sub(1 << 26);

    let mask = (g[4] >> 63).wrapping_sub(1);
    for gi in g.iter_mut() {
        *gi &= mask;
    }
    let keep = !mask;
    for (hi, gi) in h.iter_mut().zip(g.iter()) {
        *hi = (*hi & keep) | *gi;
    }

    h[0] = (h[0] | (h[1] << 26)) & 4294967295;
    h[1] = ((h[1] >> 6) | (h[2] << 20)) & 4294967295;
    h[2] = ((h[2] >> 12) | (h[3] << 14)) & 4294967295;
    h[3] = ((h[3] >> 18) | (h[4] << 8)) & 4294967295;

    let mut f = h[0] + load_u32(&key[16..]) as u64;
    h[0] = f & 4294967295;
    f = h[1] + load_u32(&key[20..]) as u64 + (f >> 32);
    h[1] = f & 4294967295;
    f = h[2] + load_u32(&key[24..]) as u64 + (f >> 32);
    h[2] = f & 4294967295;
    f = h[3] + load_u32(&key[28..]) as u64 + (f >> 32);
    h[3] = f & 4294967295;

    let mut tag = [0u8; TAG_BYTES];
    tag[0..4].copy_from_slice(&(h[0] as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(h[1] as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(h[2] as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(h[3] as u32).to_le_bytes());
    tag
}

fn poly1305_key_gen(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[..32]);
    otk
}

fn pad16(len: usize) -> usize {
    (16 - len % 16) % 16
}

fn mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(aad.len() + ciphertext.len() + 48);
    data.extend_from_slice(aad);
    data.resize(data.len() + pad16(aad.len()), 0);
    data.extend_from_slice(ciphertext);
    data.resize(data.len() + pad16(ciphertext.len()), 0);
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    data
}

fn constant_time_eq(a: &[u8; TAG_BYTES], b: &[u8; TAG_BYTES]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn seal(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_BYTES]) {
    let otk = Zeroizing::new(poly1305_key_gen(key, nonce));
    let mut ciphertext = plaintext.to_vec();
    chacha20(key, 1, nonce, &mut ciphertext);
    let tag = poly1305(&otk, &mac_data(aad, &ciphertext));
    (ciphertext, tag)
}

pub fn open(
    key: &[u8; KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_BYTES],
) -> Option<Vec<u8>> {
    let otk = Zeroizing::new(poly1305_key_gen(key, nonce));
    let expected = poly1305(&otk, &mac_data(aad, ciphertext));
    if !constant_time_eq(&expected, tag) {
        return None;
    }
    let mut plaintext = ciphertext.to_vec();
    chacha20(key, 1, nonce, &mut plaintext);
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn counting_key() -> [u8; KEY_BYTES] {
        let mut key = [0u8; KEY_BYTES];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn chacha20_block_function_vector() {
        let key = counting_key();
        let nonce: [u8; NONCE_BYTES] = hex("000000090000004a00000000").try_into().unwrap();
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(
            block[..],
            hex(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                 d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )[..]
        );
    }

    #[test]
    fn chacha20_encryption_vector() {
        let key = counting_key();
        let nonce: [u8; NONCE_BYTES] = hex("000000000000004a00000000").try_into().unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer \
                          you only one tip for the future, sunscreen would be it.";
        let expected = hex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );

        let mut buf = plaintext.to_vec();
        chacha20(&key, 1, &nonce, &mut buf);
        assert_eq!(buf[..], expected[..]);

        chacha20(&key, 1, &nonce, &mut buf);
        assert_eq!(&buf[..], &plaintext[..]);
    }

    fn chacha20_scalar_ref(
        key: &[u8; KEY_BYTES],
        counter: u32,
        nonce: &[u8; NONCE_BYTES],
        data: &mut [u8],
    ) {
        for (i, chunk) in data.chunks_mut(64).enumerate() {
            let block = chacha20_block(key, counter.wrapping_add(i as u32), nonce);
            for (b, k) in chunk.iter_mut().zip(block.iter()) {
                *b ^= *k;
            }
        }
    }

    #[test]
    fn avx2_matches_scalar_over_lengths_and_counters() {
        let key = counting_key();
        let nonce: [u8; NONCE_BYTES] = hex("000000090000004a00000000").try_into().unwrap();
        let counters = [
            0u32,
            1,
            8,
            100,
            4294967288,
            4294967291,
            4294967294,
            4294967295,
        ];
        for &counter in &counters {
            for len in 0..=2100usize {
                let mut vector: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
                    .collect();
                let mut reference = vector.clone();
                chacha20(&key, counter, &nonce, &mut vector);
                chacha20_scalar_ref(&key, counter, &nonce, &mut reference);
                assert_eq!(
                    vector, reference,
                    "keystream mismatch at counter {counter} len {len}"
                );
            }
        }
    }

    #[test]
    fn poly1305_authenticator_vector() {
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let message = b"Cryptographic Forum Research Group";
        let tag = poly1305(&key, message);
        assert_eq!(tag[..], hex("a8061dc1305136c6c22b8baf0c0127a9")[..]);
    }

    fn high_key() -> [u8; KEY_BYTES] {
        let mut key = [0u8; KEY_BYTES];
        for (i, b) in key.iter_mut().enumerate() {
            *b = 128 + i as u8;
        }
        key
    }

    #[test]
    fn poly1305_key_generation_vector() {
        let key = high_key();
        let nonce: [u8; NONCE_BYTES] = hex("000000000001020304050607").try_into().unwrap();
        assert_eq!(
            poly1305_key_gen(&key, &nonce)[..],
            hex("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646")[..]
        );
    }

    struct Example {
        key: [u8; KEY_BYTES],
        nonce: [u8; NONCE_BYTES],
        aad: Vec<u8>,
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
        tag: [u8; TAG_BYTES],
    }

    fn aead_vector() -> Example {
        Example {
            key: high_key(),
            nonce: hex("070000004041424344454647").try_into().unwrap(),
            aad: hex("50515253c0c1c2c3c4c5c6c7"),
            plaintext: b"Ladies and Gentlemen of the class of '99: If I could offer \
                         you only one tip for the future, sunscreen would be it."
                .to_vec(),
            ciphertext: hex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
                 3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
                 92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
                 3ff4def08e4b7a9de576d26586cec64b6116",
            ),
            tag: hex("1ae10b594f09e26a7e902ecbd0600691").try_into().unwrap(),
        }
    }

    #[test]
    fn aead_seal_vector() {
        let v = aead_vector();
        let (ciphertext, tag) = seal(&v.key, &v.nonce, &v.aad, &v.plaintext);
        assert_eq!(ciphertext[..], v.ciphertext[..]);
        assert_eq!(tag[..], v.tag[..]);
    }

    #[test]
    fn aead_open_vector() {
        let v = aead_vector();
        let opened = open(&v.key, &v.nonce, &v.aad, &v.ciphertext, &v.tag);
        assert_eq!(opened.as_deref(), Some(&v.plaintext[..]));
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = high_key();
        let nonce: [u8; NONCE_BYTES] = hex("000102030405060708090a0b").try_into().unwrap();
        let aad = b"quantova transport header";
        let plaintext = b"authenticated payload of arbitrary length";
        let (ciphertext, tag) = seal(&key, &nonce, aad, plaintext);
        let opened = open(&key, &nonce, aad, &ciphertext, &tag);
        assert_eq!(opened.as_deref(), Some(&plaintext[..]));
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let v = aead_vector();
        let mut forged = v.ciphertext.clone();
        forged[0] ^= 1;
        assert!(open(&v.key, &v.nonce, &v.aad, &forged, &v.tag).is_none());
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let v = aead_vector();
        let mut tag = v.tag;
        tag[TAG_BYTES - 1] ^= 128;
        assert!(open(&v.key, &v.nonce, &v.aad, &v.ciphertext, &tag).is_none());
    }

    #[test]
    fn open_rejects_wrong_nonce() {
        let v = aead_vector();
        let mut nonce = v.nonce;
        nonce[0] ^= 1;
        assert!(open(&v.key, &nonce, &v.aad, &v.ciphertext, &v.tag).is_none());
    }

    #[test]
    fn open_rejects_wrong_key() {
        let v = aead_vector();
        let mut key = v.key;
        key[0] ^= 1;
        assert!(open(&key, &v.nonce, &v.aad, &v.ciphertext, &v.tag).is_none());
    }

    #[test]
    fn seal_is_stable_for_fixed_inputs() {
        let v = aead_vector();
        let first = seal(&v.key, &v.nonce, &v.aad, &v.plaintext);
        let second = seal(&v.key, &v.nonce, &v.aad, &v.plaintext);
        assert_eq!(first.0, second.0);
        assert_eq!(first.1, second.1);
    }
}
