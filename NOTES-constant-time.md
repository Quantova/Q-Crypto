# Constant time review

This is a read only review of the sign, verify, and decapsulation paths for data dependent branching and for memory access that depends on secret material. It changes no cryptographic code. It records where the current code is already constant time with respect to secret keys and where a later hardening pass should look. Nothing here is a conformance defect. Every primitive still matches the NIST vectors committed under `vectors/`.

## SHA-3 and SHAKE

The Keccak permutation in `qudros_f1600` runs a fixed twenty four rounds of rotations and bitwise operations with compile time constant offsets. `absorb_byte` and `squeeze_byte` index by a position that tracks only the offset and the rate, never by a message byte. Running time depends on input length and output length alone, which is the standard and accepted property for a hash. No secret dependent branch or table lookup exists in the sponge. This core is constant time and every other primitive inherits it for the parts that route secrets through SHAKE.

## ML-KEM-768 decapsulation

The implicit rejection is written in constant time and this is the property that matters most for a KEM. The re encryption check uses `ct_eq`, which folds every byte difference into one accumulator before reducing to a mask, so it does not stop at the first mismatch. The returned shared secret is selected arithmetically with `(keep & k_prime) | (!keep & k_bar)`, so the reject case is not taken by control flow. This part is correct.

Underneath that layer the polynomial arithmetic over the secret key is not constant time. `add_q` and `sub_q` reduce with a branch on the reduced value, `mul_q` reduces with the `%` operator, and `compress` and `decompress` use integer division. `kpke_decrypt` runs all of these over the secret vector `s` on every decapsulation. On a processor where the taken branch or the divider timing depends on operands this is a timing and cache channel on the secret key. Reference ML-KEM code avoids it with Montgomery or Barrett reduction and a branchless conditional subtraction. This shared arithmetic is the first place a hardening pass should look.

`poly12_canonical` uses `all`, which stops at the first non canonical coefficient. For an honestly generated key every coefficient is canonical, so the scan always runs to the end, and only an attacker supplied malformed key can short circuit it. The observable is the attacker input rather than the honest secret, so this is minor, and it is noted for completeness.

## ML-DSA-65 signing

The rejection loop in `sign_with_mu` repeats until a candidate passes the norm bounds, so the iteration count depends on secret derived values. This follows the structure of the reference Dilithium signer and does not hand over the key, but it is data dependent control flow and the number of attempts is visible through timing.

Inside each attempt the field arithmetic is value dependent in the same way as the KEM. `mul_q` reduces through `rem_euclid`, `add_q` and `sub_q` branch on the reduced value, and `decompose`, `center`, `inf_norm`, `power2round`, `low_bits`, and `make_hint` branch on coefficients that come from the secret key and from the secret mask. `sample_in_ball` rejects candidate indices in a data dependent loop over SHAKE output. None of these leak the key the way a plain byte comparison of a secret would, yet the secret path as a whole is not constant time at the arithmetic level, and it deserves a closer look before any deployment exposed to a local timing or microarchitectural attacker.

The secret material carries a `Drop` that zeroizes it and a `Debug` that prints a fixed redaction string, so the key is cleared after use and is not printed by accident.

## ML-DSA-65 verification

Verification reads only the public key, the message, and the signature. It holds no secret, so its branches have no secret to expose. The final decision compares the recomputed challenge against the signature challenge with the ordinary `==`, which can return on the first differing byte, but both operands are public so the early return reveals nothing sensitive. `sig_decode` rejects a malformed hint or an out of range field by returning early, again over public data.

## SLH-DSA-SHAKE-192s signing and verification

The secret key reaches the algorithm only through the SHAKE based `prf` and `prf_msg`, and Keccak is constant time as noted above, so the secret seed never steers a branch or an index. The hypertree indices, the WOTS chain lengths, and the FORS leaf positions all come from the message digest, which is public once a signature exists, so their effect on timing does not expose the key. `prf` and `prf_msg` zeroize their input buffers after hashing. The verify path compares the recomputed root against the public root with `==` over public data. Of the three schemes this one is closest to constant time with respect to the secret key.

## Summary

The highest value hardening target is the shared modular arithmetic used by ML-KEM decapsulation and ML-DSA signing, meaning the value dependent reduction in `add_q`, `sub_q`, and `mul_q`, and the integer division in the ML-KEM `compress` and `decompress`. The KEM implicit rejection and the secret zeroization are already handled correctly. SLH-DSA and the Keccak core are already constant time with respect to secret material. None of this is a functional or a conformance problem and no cryptographic code was touched by this review.
