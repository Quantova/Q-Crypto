# Benchmarks

Signature and KEM throughput, and hashing rates. These numbers feed two things downstream:

- QVM gas calibration for the native PQ opcodes.
- The phone-class validator resource budget (max verify time on a reference 2020 mid-range phone),
  enforced as a consensus parameter by Quantova-Bench.

The benchmark report is committed alongside the `v0.1.0` tag.
