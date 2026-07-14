# NIST Known-Answer Test Vectors

The official NIST KATs for each primitive are checked in here and every implementation is validated
against them before it is considered done:

- `sha3/` — FIPS 202 (SHA3-256, SHAKE128/256)
- `ml_dsa/` — FIPS 204
- `ml_kem/` — FIPS 203
- `slh_dsa/` — FIPS 205
- `fn_dsa/` — added on FN-DSA final publication

Frozen cross-repo vectors (codec, addresses, tx encoding) live separately in Quantova-Conformance.
