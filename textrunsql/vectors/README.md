# Test vectors

All secrets in this directory are synthetic public test material. Never use these keys, seeds, DEKs, nonces, or envelopes outside tests.

## `mlkem768-acvp.txt`

This is a minimal text projection of NIST ACVP-Server ML-KEM-768 sample cases. NIST is the source of the original vectors and does not endorse this project or projection.

- source repository: `https://github.com/usnistgov/ACVP-Server`
- source commit: `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`
- algorithm/revision: ML-KEM-768, FIPS 203
- selected cases: keyGen `tgId=2`, `tcId=26`; encapDecap `tgId=2`, `tcId=26`
- projection: selected byte strings were copied mechanically into lowercase-independent `name=hex` fields; field names and container syntax changed, values did not
- projected file SHA-256: `ad97e8676f50eb3b9b38e792e3c78ae9228438e68c322740c83fbc60992333ef`
- consumer: OpenSSL 3.6.3 through `test/test_acvp.c`
- expected classification: key generation, encapsulation, and decapsulation accept and match every expected byte
- notice: [NIST-NOTICE.txt](NIST-NOTICE.txt)

The six source JSON paths and SHA-256 values are recorded in [NIST-NOTICE.txt](NIST-NOTICE.txt). To reproduce the projection, obtain those exact files at the pinned commit, select the named group and case from key generation and encapsulation/decapsulation, and emit the fields in the order present in `mlkem768-acvp.txt`.

## `envelope-v1.hex`

This is one complete deterministic format-version-1, suite-1 envelope encoded as 2472 lowercase hexadecimal characters plus newline.

- producer/consumer: OpenSSL 3.6.3 through `test/test_acvp.c`
- recipient key seed and deterministic encapsulation input: fields in `mlkem768-acvp.txt`
- context: UTF-8 `textrunsql/vector/customer-0001/database-0001`
- DEK: bytes `a0` through `bf`
- nonce: bytes `00` through `0b`
- file SHA-256: `7f730c7ffa63e2c7c2300f2262282eb2445b4ab143ff0c0cb15732d0df977030`
- expected classification: exact byte match and successful authenticated open

Reproduce from the add-on directory:

```sh
make test
build/test_acvp --print-envelope
```

The printed line must equal `envelope-v1.hex`. Any format, suite, KDF, associated-data, provider-encoding, or deterministic-input change invalidates this vector and requires an intentional new identifier or reviewed vector update.
