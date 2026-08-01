// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::fs::File;
use std::io::Read;

pub(crate) fn fill_random(buf: &mut [u8]) {
    let mut file =
        File::open("/dev/urandom").expect("Q-Crypto: cannot open /dev/urandom for OS randomness");
    file.read_exact(buf)
        .expect("Q-Crypto: short read from /dev/urandom");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_random_is_not_constant_and_fills_the_buffer() {
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        fill_random(&mut a);
        fill_random(&mut b);
        assert_ne!(a, b, "two OS draws must not be equal");
        assert!(a.iter().any(|&x| x != 0), "the buffer must be written");
    }
}
