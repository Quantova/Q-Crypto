// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::sync::atomic::{compiler_fence, Ordering};

pub(crate) trait Zeroize {
    fn zeroize(&mut self);
}

fn volatile_zero<T: Copy + Default>(slots: &mut [T]) {
    let zero = T::default();
    for slot in slots.iter_mut() {
        unsafe { core::ptr::write_volatile(slot, zero) }
    }
}

fn wide_zero<T: Copy + Default>(slots: &mut [T]) {
    let (head, body, tail) = unsafe { slots.align_to_mut::<u128>() };
    volatile_zero(head);
    volatile_zero(body);
    volatile_zero(tail);
    compiler_fence(Ordering::SeqCst);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        wide_zero(self);
    }
}

impl Zeroize for [i32] {
    fn zeroize(&mut self) {
        wide_zero(self);
    }
}

impl Zeroize for [u32] {
    fn zeroize(&mut self) {
        wide_zero(self);
    }
}

impl Zeroize for [u64] {
    fn zeroize(&mut self) {
        wide_zero(self);
    }
}

impl<const M: usize> Zeroize for [[i32; M]] {
    fn zeroize(&mut self) {
        for row in self.iter_mut() {
            row[..].zeroize();
        }
    }
}

pub(crate) struct SecretPolys<const M: usize> {
    polys: Vec<[i32; M]>,
}

impl<const M: usize> SecretPolys<M> {
    pub(crate) fn new(polys: Vec<[i32; M]>) -> Self {
        SecretPolys { polys }
    }
}

impl<const M: usize> Drop for SecretPolys<M> {
    fn drop(&mut self) {
        self.polys[..].zeroize();
    }
}

impl<const M: usize> core::ops::Deref for SecretPolys<M> {
    type Target = Vec<[i32; M]>;
    fn deref(&self) -> &Self::Target {
        &self.polys
    }
}

impl<const M: usize> core::ops::DerefMut for SecretPolys<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.polys
    }
}

pub(crate) struct Zeroizing<T: AsMut<[u8]>> {
    value: T,
}

impl<T: AsMut<[u8]>> Zeroizing<T> {
    pub(crate) fn new(value: T) -> Self {
        Zeroizing { value }
    }
}

impl<T: AsMut<[u8]>> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.value.as_mut().zeroize();
    }
}

impl<T: AsMut<[u8]>> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: AsMut<[u8]>> core::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Zeroizing(redacted)")
    }
}

pub struct SecretBytes<const N: usize> {
    bytes: Box<[u8; N]>,
}

impl<const N: usize> SecretBytes<N> {
    pub fn zeroed() -> Self {
        SecretBytes {
            bytes: Box::new([0u8; N]),
        }
    }

    pub fn from_bytes(bytes: &[u8; N]) -> Self {
        let mut out = Self::zeroed();
        out.bytes.copy_from_slice(bytes);
        out
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != N {
            return None;
        }
        let mut out = Self::zeroed();
        out.bytes.copy_from_slice(bytes);
        Some(out)
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.bytes[..].zeroize();
    }
}

impl<const N: usize> core::ops::Deref for SecretBytes<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> core::ops::DerefMut for SecretBytes<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..]
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            diff |= a ^ b;
        }
        core::hint::black_box(diff) == 0
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_clears_every_byte() {
        let mut buffer = [7u8; 64];
        buffer[..].zeroize();
        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_clears_every_word() {
        let mut buffer = [123i32; 32];
        buffer[..].zeroize();
        assert!(buffer.iter().all(|&w| w == 0));
    }

    #[test]
    fn zeroize_clears_every_lane() {
        let mut state = [0x0123_4567_89ab_cdefu64; 25];
        state[..].zeroize();
        assert!(state.iter().all(|&w| w == 0));
    }

    #[test]
    fn wrapper_exposes_the_inner_bytes() {
        let holder = Zeroizing::new([9u8; 16]);
        assert_eq!(&holder[..], &[9u8; 16][..]);
    }

    #[test]
    fn wrapper_debug_hides_the_bytes() {
        let holder = Zeroizing::new([200u8; 8]);
        assert_eq!(format!("{:?}", holder), "Zeroizing(redacted)");
    }

    #[test]
    fn zeroize_clears_a_slice_of_polynomials() {
        let mut polys = [[9i32; 8]; 4];
        polys[..].zeroize();
        assert!(polys.iter().all(|row| row.iter().all(|&c| c == 0)));
    }

    #[test]
    fn secret_polys_exposes_and_wipes_every_coefficient() {
        let mut guard = SecretPolys::new(vec![[5i32; 4], [6i32; 4]]);
        assert_eq!(guard[0][0], 5);
        assert_eq!(guard[1][3], 6);
        guard.iter_mut().next().unwrap()[0] = 42;
        assert_eq!(guard[0][0], 42);
        guard.polys[..].zeroize();
        assert!(guard.polys.iter().all(|row| row.iter().all(|&c| c == 0)));
    }
}
