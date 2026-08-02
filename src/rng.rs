// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use std::fs::File;
use std::io::Read;

#[cfg(target_os = "linux")]
fn os_fill(buf: &mut [u8]) -> bool {
    extern "C" {
        fn getrandom(
            buf: *mut core::ffi::c_void,
            buflen: usize,
            flags: core::ffi::c_uint,
        ) -> isize;
    }
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = unsafe {
            getrandom(
                buf[filled..].as_mut_ptr() as *mut core::ffi::c_void,
                buf.len() - filled,
                0,
            )
        };
        if n <= 0 {
            return false;
        }
        filled += n as usize;
    }
    true
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn os_fill(buf: &mut [u8]) -> bool {
    extern "C" {
        fn getentropy(buf: *mut core::ffi::c_void, buflen: usize) -> core::ffi::c_int;
    }
    for chunk in buf.chunks_mut(256) {
        let rc = unsafe { getentropy(chunk.as_mut_ptr() as *mut core::ffi::c_void, chunk.len()) };
        if rc != 0 {
            return false;
        }
    }
    true
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn os_fill(_buf: &mut [u8]) -> bool {
    false
}

pub(crate) fn fill_random(buf: &mut [u8]) {
    if os_fill(buf) {
        return;
    }
    let mut file = File::open("/dev/urandom")
        .expect("Q-Crypto: no OS entropy source (CSPRNG syscall and /dev/urandom both unavailable)");
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

    #[test]
    fn fill_random_has_high_entropy_and_no_repeats() {
        let mut buf = [0u8; 4096];
        fill_random(&mut buf);

        let mut seen = [false; 256];
        for &byte in buf.iter() {
            seen[byte as usize] = true;
        }
        let distinct = seen.iter().filter(|&&s| s).count();
        assert!(
            distinct >= 200,
            "expected wide byte coverage from a CSPRNG, saw only {distinct} distinct values"
        );

        let set_bits: u32 = buf.iter().map(|b| b.count_ones()).sum();
        let total_bits = (buf.len() * 8) as u32;
        assert!(
            set_bits > total_bits * 45 / 100 && set_bits < total_bits * 55 / 100,
            "set-bit fraction {set_bits}/{total_bits} is outside a plausible unbiased band"
        );

        let mut draws: Vec<[u8; 32]> = Vec::new();
        for _ in 0..16 {
            let mut d = [0u8; 32];
            fill_random(&mut d);
            assert!(
                !draws.contains(&d),
                "independent CSPRNG draws must not collide"
            );
            draws.push(d);
        }
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    #[test]
    fn os_fill_syscall_path_is_available_and_random() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        assert!(os_fill(&mut a), "platform CSPRNG syscall must be available");
        assert!(os_fill(&mut b), "platform CSPRNG syscall must be available");
        assert_ne!(a, b, "two syscall draws must not be equal");
        assert!(a.iter().any(|&x| x != 0), "the buffer must be written");
    }
}
