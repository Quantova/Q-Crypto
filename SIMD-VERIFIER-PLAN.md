# Vectorising the ML-DSA verifier

The plan for the focused, reviewed effort on the `simd-verifier` branch. The goal is to cut the cost of a signature verification without changing a single accept or reject verdict.

## What we are speeding up, measured

Profiled on rack04, a verify splits almost evenly:

- **expand_a, about half.** Rebuilds the public matrix from the key with SHAKE128, which is thirty independent Keccak streams per verify.
- **the transform, about half.** Twelve forward and six inverse number theoretic transforms plus thirty six pointwise products.
- the final hash is negligible.

The scalar modular reduction is **not** a target. The compiler already lowers a modulo by a constant to a multiply and shift, confirmed by a proven identical Barrett reduction that gave no speedup. The win is data parallelism across coefficients and across hash streams, which only SIMD delivers.

## The correctness gate, already in place

Every step is gated by, in order of strength:

1. The FIPS-204 known answer vectors for keygen, sign, and verify, end to end.
2. `ntt_then_inv_ntt_is_the_identity` and `pointwise_product_is_negacyclic_convolution`, which pin the meaning of the transform independent of its internal representation.
3. A per step differential test, the new vectorised routine against the untouched scalar reference over random inputs and the boundaries.

A step ships only when all three are green. The scalar reference stays in the tree as the oracle.

## Sequence

1. **SIMD modular reduction unit.** A branchless Barrett or Montgomery reduction over a lane of products, in `std::arch` SSE4.1 with an AVX2 path behind runtime detection. Verified in isolation against the scalar reduction across the whole input range. Branchless so it is data independent.
2. **SIMD pointwise product.** Built on step 1. Verified by the differential test and the convolution gate. Smallest useful speedup, lowest risk, do it first.
3. **SIMD transform butterflies.** Forward and inverse, sharing the reduction. The inner loop over a butterfly block is independent per lane. Verified by the round trip and convolution gates.
4. **Multi lane Keccak for expand_a.** The thirty SHAKE streams are independent, so run two at a time on SSE2 and four at a time on AVX2. This is the other half. Verified by a differential test of the multi lane permutation against the scalar one, then the known answer vectors.
5. **Runtime dispatch and fallback.** `is_x86_feature_detected!` selects the widest available path, with the scalar reference as the fallback, so the node stays correct on any CPU and faster where AVX2 or AVX-512 exists.

## Constant time

Verification runs only on public data, the public key, the signature, and the message, so a timing side channel in verify leaks nothing. But the transform is shared with signing, which touches the secret key, so every vectorised arithmetic step must stay branchless and data independent. No data dependent shuffles, no early exits inside the shared routines. This is a review checklist item, not an afterthought.

## Expected gain

On the SSE only 2012 Sandy Bridge racks, about 2x on verify, which takes execution past 25k. On a modern AVX2 or AVX-512 validator the same code is four to eight times wider and clears it comfortably. The vectorised paths are additive, the scalar reference remains for correctness and for machines without the features.

## Review checklist

- All known answer vectors green, both transform invariants green, every differential unit test green.
- Each `unsafe` block reviewed for lane counts, alignment, and the reduction bound.
- The shared transform routines audited for data independence.
- A benchmark before and after on the same host, verify_bench and sustained_tps, with the numbers recorded.
