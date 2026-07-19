# Design

## Security boundary

TextrunSQL protects one random 32-byte SQLCipher database encryption key (DEK) for one ML-KEM-768 recipient. SQLCipher remains responsible for page encryption, page authentication, database-format compatibility, and SQLite integration. The calling product remains responsible for filesystem lifecycle, key custody, metadata durability, recovery, and authenticated selection of the context identifier.

The design addresses disclosure or undetected modification of a stored envelope and substitution across recipients or application contexts. It assumes the recipient private key, OpenSSL process state, SQLCipher process state, operating system, compiler, and caller-supplied context are trusted. It does not protect a running process whose memory or recipient private key is compromised, prevent rollback to an older valid database-and-envelope pair, or make database publication atomic.

## Data flow

Seal:

1. The caller generates a DEK with `textrunsql_pq_dek_generate`.
2. TextrunSQL hashes the recipient public key and caller context with SHA-256.
3. OpenSSL ML-KEM-768 encapsulation produces a 1088-byte ciphertext and 32-byte shared secret.
4. HKDF-SHA-256 derives a 32-byte key-encryption key from the shared secret, the context hash as salt, and the fixed info string `TextrunSQL/PQEnvelope/v1/ML-KEM-768/HKDF-SHA-256/AES-256-GCM`.
5. AES-256-GCM encrypts the DEK with a random 12-byte nonce. The canonical header, recipient identifier, context hash, KEM ciphertext, and nonce are associated data.
6. TextrunSQL copies the complete envelope to caller memory only after every operation succeeds.

Open:

1. TextrunSQL validates exact length, magic, flags, reserved field, declared lengths, version, and suite before provider use.
2. It recomputes and constant-time compares the recipient identifier and context hash.
3. OpenSSL decapsulates the KEM ciphertext, derives the same key-encryption key, and authenticates and decrypts the DEK.
4. The caller's DEK output remains zero until every check succeeds.
5. The caller may pass the DEK through `textrunsql_pq_key_sqlcipher`, which constructs SQLCipher's exact lowercase `x'<64 hex>'` raw-key syntax in a fixed stack buffer, invokes `sqlite3_key_v2`, and cleanses the entire temporary buffer.

## Ownership and secret lifetime

Opaque key objects own their OpenSSL `EVP_PKEY` and cached public encoding. `textrunsql_pq_key_free` releases the provider key and cleanses the object. Exported private-key bytes, generated or opened DEKs, application contexts, and envelopes belong to the caller.

Provider seeds and deterministic encapsulation inputs exist only in test builds. Shared secrets, derived key-encryption keys, candidate plaintexts, temporary envelopes, failed outputs, and raw SQLCipher keyspecs are cleansed on owned success and failure paths with `OPENSSL_cleanse`. Production objects contain no deterministic-randomness or fault-injection entry points.

## Errors

The public result classes distinguish misuse, insufficient output capacity, unsupported capability or format, allocation failure, structural format failure, authentication failure, provider failure, and SQLCipher rejection. KEM decapsulation failure, recipient mismatch, context mismatch, and AEAD rejection do not reveal a DEK. Detailed OpenSSL errors are cleared at API boundaries and are not exposed as a decapsulation oracle.

## Provider and concurrency

The implementation uses the process-default OpenSSL library context and provider selection. It does not load providers, change global properties, or fall back to another suite. Applications that require a restricted provider configuration must establish and qualify that process policy before calling TextrunSQL.

Keys are immutable after construction. Independent key objects may be used concurrently. Access to the same opaque key object must be externally serialized; this version makes no shared-object concurrency guarantee.

## Versioning

Format version 1 and suite 1 have one canonical interpretation. Unknown versions and suites are rejected. Any field, algorithm, key derivation, associated-data rule, or lifecycle change that alters meaning requires a new format or suite identifier and new vectors. Migration must be designed and tested before changing stored customer data.

## Assurance boundary

The repository includes official NIST ACVP sample projection checks, deterministic language-neutral envelope bytes, exhaustive single-bit envelope corruption, structural-boundary tests, fault injection, an exact-DEK all-byte matrix, SQLCipher interoperability, ASan/UBSan, and a libFuzzer target. These checks establish the behavior of the tested source and toolchain; they do not substitute for independent cryptographic/protocol review, side-channel assessment, supported-platform qualification, or delivery-artifact review.
