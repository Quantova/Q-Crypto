# Test Vectors

These files hold the fixed test values that check the Quantova cryptography against the published standards. Every value here is public by design. None of it is a private key and none of it controls an account or any funds.

The SHA3 and SHAKE files come from the NIST CAVP FIPS 202 set. The ML KEM files come from the NIST ACVP FIPS 203 set. Each file pins an input and the answer the standard requires, so a reader who runs the code over the input and compares the result knows the code matches the standard. A scanner that reads these as keys is wrong. They are the proof of correctness, not a secret.

The real validator and account keys are made on the machine that runs the node. The node draws each key from the operating system random source on first run and writes it to a local keystore file that the operator holds. That file is never part of the source and it never leaves the machine.
