# TextrunSQL changes

## 0.1.0

- Added a C11 post-quantum envelope for one random 32-byte SQLCipher DEK using ML-KEM-768, HKDF-SHA-256, and AES-256-GCM through OpenSSL 3.5 or later.
- Added opaque recipient key generation/import/export, cryptographic DEK generation, in-memory envelope seal/open, and exact raw-key handoff through `sqlite3_key_v2`.
- Added a fixed 1236-byte format version 1 and suite 1 bound to recipient and application context.
- Added focused C and Tcl tests, official NIST ACVP sample projection checks, deterministic envelope bytes, sanitizer and libFuzzer lanes, and a public-header SQLCipher consumer.

This changelog covers downstream changes only. SQLCipher and SQLite history remains in the inherited upstream changelogs.
