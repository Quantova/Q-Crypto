# Test vectors

The official NIST known answer tests for each primitive are checked in here, and every implementation is validated against them before it is considered done. The folders cover SHA 3 from FIPS 202, ML DSA from FIPS 204, ML KEM from FIPS 203, and SLH DSA from FIPS 205. The FN DSA vectors are added once FN DSA is published in final form.

The ML DSA, ML KEM, and SLH DSA folders are drawn from the NIST ACVP Server generation and validation vectors, one line per test case, and each file names the vsId and the source tcIds it was taken from. The SHA 3 folder is drawn from the NIST CAVP FIPS 202 byte oriented test vectors, and it covers the short messages, the multi block long messages, and for the SHAKE functions a range of output lengths including a squeeze that crosses the sponge rate. The fields on each line are documented in the header comment of the file.

The frozen cross repository vectors for the codec, the addresses, and the transaction encoding live separately in the Quantova Conformance repository.
