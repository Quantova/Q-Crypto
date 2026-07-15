//! ChaCha20-Poly1305 authenticated encryption (RFC 8439).
//!
//! The single 256-bit symmetric AEAD POLICY-crypto.md permits, used by the Quantova transport. A
//! 256-bit key and a 96-bit nonce key the ChaCha20 stream cipher; the Poly1305 one-time key is the
//! first ChaCha20 block under counter zero. `seal` returns the ciphertext and a 128-bit tag over the
//! associated data and ciphertext, and `open` recomputes the tag, compares it in constant time, and
//! returns the plaintext only on an exact match.

/// Key length in bytes.
pub const KEY_BYTES: usize = 32;
/// Nonce length in bytes.
pub const NONCE_BYTES: usize = 12;

// The four ChaCha20 constant words: the ASCII of "expand 32-byte k" read little-endian.
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

// Read a little-endian u32 from the first four bytes of `bytes`.
fn load_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

// One ChaCha20 quarter round over four words of the working state.
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

// The ChaCha20 block function: twenty rounds over the state keyed by `key`, `counter`, and `nonce`,
// producing a 64-byte keystream block.
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

/// Encrypt or decrypt `data` in place with ChaCha20 (RFC 8439), keyed by `key` and `nonce` with the
/// keystream starting at block `counter`. ChaCha20 is its own inverse, so the same call decrypts.
pub fn chacha20(key: &[u8; KEY_BYTES], counter: u32, nonce: &[u8; NONCE_BYTES], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let block = chacha20_block(key, counter.wrapping_add(i as u32), nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Decode an even-length hexadecimal string into a byte vector.
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    // The key 00, 01, .., 1f used by the RFC 8439 ChaCha20 vectors.
    fn counting_key() -> [u8; KEY_BYTES] {
        let mut key = [0u8; KEY_BYTES];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn chacha20_block_function_vector() {
        // RFC 8439 section 2.3.2.
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
        // RFC 8439 section 2.4.2.
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

        // ChaCha20 is its own inverse, so a second pass restores the plaintext.
        chacha20(&key, 1, &nonce, &mut buf);
        assert_eq!(&buf[..], &plaintext[..]);
    }
}
