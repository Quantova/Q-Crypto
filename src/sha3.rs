//! SHA-3 and SHAKE (FIPS 202). Implemented first - every other primitive and the PQ VRF build on it.

// Round constants for the iota step of Keccak-f[1600] (FIPS 202, 24 rounds).
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// Rotation offsets for the rho step, ordered to match the pi lane traversal below.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

// Lane permutation for the pi step.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

// The Keccak-f[1600] permutation over a state of 25 lanes of 64 bits.
fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..24 {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        // Rho and Pi
        let mut last = state[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = state[j];
            state[j] = last.rotate_left(RHO[i]);
            last = tmp;
        }

        // Chi
        for y in 0..5 {
            let row = y * 5;
            let mut plane = [0u64; 5];
            for x in 0..5 {
                plane[x] = state[row + x];
            }
            for x in 0..5 {
                state[row + x] = plane[x] ^ ((!plane[(x + 1) % 5]) & plane[(x + 2) % 5]);
            }
        }

        // Iota
        state[0] ^= RC[round];
    }
}

// Absorb a single byte into the lane state at the given rate offset.
fn absorb_byte(state: &mut [u64; 25], offset: usize, byte: u8) {
    let lane = offset / 8;
    let shift = 8 * (offset % 8);
    state[lane] ^= (byte as u64) << shift;
}

// Read a single byte of the lane state at the given rate offset.
fn squeeze_byte(state: &[u64; 25], offset: usize) -> u8 {
    let lane = offset / 8;
    let shift = 8 * (offset % 8);
    (state[lane] >> shift) as u8
}

// The Keccak sponge with byte rate `rate` and FIPS 202 domain byte `domain`.
// `domain` is 0x06 for SHA3 (bits 01 then pad10*1) and 0x1f for SHAKE (bits 1111 then pad10*1).
fn sponge(rate: usize, domain: u8, input: &[u8], output: &mut [u8]) {
    let mut state = [0u64; 25];

    // Absorb full blocks, permuting whenever the rate boundary is reached.
    let mut offset = 0;
    for &byte in input {
        absorb_byte(&mut state, offset, byte);
        offset += 1;
        if offset == rate {
            keccak_f1600(&mut state);
            offset = 0;
        }
    }

    // Pad: domain bits at the current offset, high bit at the last rate byte.
    absorb_byte(&mut state, offset, domain);
    absorb_byte(&mut state, rate - 1, 0x80);
    keccak_f1600(&mut state);

    // Squeeze the requested number of output bytes.
    let mut produced = 0;
    let mut pos = 0;
    while produced < output.len() {
        if pos == rate {
            keccak_f1600(&mut state);
            pos = 0;
        }
        output[produced] = squeeze_byte(&state, pos);
        produced += 1;
        pos += 1;
    }
}

/// SHA3-256 (FIPS 202): fixed 32-byte digest, rate 136 bytes.
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sponge(136, 0x06, input, &mut out);
    out
}

/// SHA3-512 (FIPS 202): fixed 64-byte digest, rate 72 bytes.
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    sponge(72, 0x06, input, &mut out);
    out
}

/// SHAKE128 (FIPS 202): extendable output, rate 168 bytes. Fills `output` fully.
pub fn shake128(input: &[u8], output: &mut [u8]) {
    sponge(168, 0x1f, input, output);
}

/// SHAKE256 (FIPS 202): extendable output, rate 136 bytes. Fills `output` fully.
pub fn shake256(input: &[u8], output: &mut [u8]) {
    sponge(136, 0x1f, input, output);
}
