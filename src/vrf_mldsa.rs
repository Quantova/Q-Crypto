//! Lattice-based post-quantum VRF (ML-DSA). The second construction on the same interface as the
//! hash-based `vrf` module. Both are kept; the benchmark chooses which one consensus defaults to.
//!
//! The key pair is an ML-DSA (FIPS 204) key pair. The proof for an input is the deterministic
//! ML-DSA signature over that input, and the output is SHAKE256 of the proof reduced to a fixed
//! 32 bytes. Deterministic signing uses the all-zero randomizer of FIPS 204, so the same secret key
//! and input always produce one signature, and therefore one output; because ML-DSA is unforgeable,
//! the output is bound to the key pair. Verification rechecks the signature over the input and
//! recomputes SHAKE256 of the proof, accepting only when the signature verifies and the recomputed
//! output equals the supplied output.
//!
//! The STARK proof wrapper of the specification is not part of this construction. It shrinks the
//! proof size and is deferred; it changes neither the output nor the verification here.

use crate::ml_dsa;
use crate::sha3::shake256;

/// Secret key length in bytes (the ML-DSA secret key).
pub const SECRET_KEY_BYTES: usize = ml_dsa::SECRET_KEY_BYTES;
/// Public key length in bytes (the ML-DSA public key).
pub const PUBLIC_KEY_BYTES: usize = ml_dsa::PUBLIC_KEY_BYTES;
/// Proof length in bytes (one ML-DSA signature).
pub const PROOF_BYTES: usize = ml_dsa::SIGNATURE_BYTES;
/// Output length in bytes (fixed SHAKE256 output).
pub const OUTPUT_BYTES: usize = 32;

// FIPS 204 deterministic signing uses an all-zero randomizer.
const DETERMINISTIC_RND: [u8; 32] = [0u8; 32];

// The VRF output is a fixed-length SHAKE256 digest of the proof.
fn output_from_proof(proof: &[u8; PROOF_BYTES]) -> [u8; OUTPUT_BYTES] {
    let mut output = [0u8; OUTPUT_BYTES];
    shake256(proof, &mut output);
    output
}

/// Generate a VRF key pair from a caller-supplied seed.
///
/// The seed is folded with SHAKE256 into the 32-byte ML-DSA key generation seed, and the resulting
/// ML-DSA key pair is returned as (secret key, public key).
pub fn keygen(seed: &[u8]) -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
    let mut mldsa_seed = [0u8; ml_dsa::SEED_BYTES];
    shake256(seed, &mut mldsa_seed);
    let (pk, sk) = ml_dsa::keygen(&mldsa_seed);
    (sk, pk)
}

/// Evaluate the VRF on `input` with the secret key.
///
/// Returns the fixed-length output and the proof. The proof is the deterministic ML-DSA signature
/// over the input, so the same secret key and input always produce the same proof and output.
pub fn prove(sk: &[u8; SECRET_KEY_BYTES], input: &[u8]) -> ([u8; OUTPUT_BYTES], [u8; PROOF_BYTES]) {
    let proof = ml_dsa::sign_internal(sk, input, &DETERMINISTIC_RND);
    let output = output_from_proof(&proof);
    (output, proof)
}

/// Verify a VRF output and proof for `input` under the public key.
///
/// Accepts only when the ML-DSA signature over the input verifies and SHAKE256 of the proof equals
/// the supplied output.
pub fn verify(
    pk: &[u8; PUBLIC_KEY_BYTES],
    input: &[u8],
    output: &[u8; OUTPUT_BYTES],
    proof: &[u8; PROOF_BYTES],
) -> bool {
    if !ml_dsa::verify_internal(pk, input, proof) {
        return false;
    }
    output_from_proof(proof) == *output
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed key pair for the tests.
    fn key_pair() -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
        keygen(b"quantova mldsa vrf test seed")
    }

    #[test]
    fn verify_accepts_valid_output_and_proof() {
        let (sk, pk) = key_pair();
        let input = b"committee sampling input";
        let (output, proof) = prove(&sk, input);
        assert!(verify(&pk, input, &output, &proof));
    }

    #[test]
    fn output_is_deterministic() {
        let (sk, _pk) = key_pair();
        let input = b"the same input every time";
        let (output_a, proof_a) = prove(&sk, input);
        let (output_b, proof_b) = prove(&sk, input);
        assert_eq!(output_a, output_b);
        assert_eq!(&proof_a[..], &proof_b[..]);
    }

    #[test]
    fn verify_rejects_wrong_output() {
        let (sk, pk) = key_pair();
        let input = b"an input";
        let (mut output, proof) = prove(&sk, input);
        output[0] ^= 1;
        assert!(!verify(&pk, input, &output, &proof));
    }

    #[test]
    fn verify_rejects_wrong_proof() {
        let (sk, pk) = key_pair();
        let input = b"an input";
        let (output, mut proof) = prove(&sk, input);
        proof[0] ^= 1;
        assert!(!verify(&pk, input, &output, &proof));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (sk, pk) = key_pair();
        let (_other_sk, other_pk) = keygen(b"a different signer");
        let input = b"an input";
        let (output, proof) = prove(&sk, input);
        // The output and proof are valid under this signer's own key.
        assert!(verify(&pk, input, &output, &proof));
        // They must not verify under an unrelated public key.
        assert!(!verify(&other_pk, input, &output, &proof));
    }

    #[test]
    fn verify_rejects_wrong_input() {
        let (sk, pk) = key_pair();
        let (output, proof) = prove(&sk, b"the real input");
        assert!(!verify(&pk, b"a different input", &output, &proof));
    }

    #[test]
    fn different_inputs_give_different_outputs() {
        let (sk, _pk) = key_pair();
        let (output_a, _) = prove(&sk, b"input one");
        let (output_b, _) = prove(&sk, b"input two");
        assert_ne!(output_a, output_b);
    }
}
