# TextrunSQL post-quantum key envelope

This subtree adds an optional post-quantum protection layer for a random 32-byte SQLCipher database encryption key (DEK). SQLCipher continues to encrypt database pages; TextrunSQL seals and opens the DEK before the caller applies it through SQLCipher's public raw-key interface.

The implementation is private pre-1.0 source. Format version 1 is exact and tested, but compatibility is not promised across a future pre-1.0 format change. A format or suite change requires a new identifier and explicit migration tooling before customer data uses it.

## Dependencies

- SQLCipher Community 4.17.0 from this repository;
- OpenSSL 3.5 or later with ML-KEM-768, HKDF-SHA-256, AES-256-GCM, and a cryptographic random source;
- a C11 compiler; and
- Tcl 8.6 when building the inherited SQLCipher test fixture.

OpenSSL is linked as an external dependency and is not vendored. The add-on uses public EVP, provider, KDF, cipher, digest, and random APIs. It does not select a fallback algorithm when a required operation is unavailable.

## Build on macOS with Homebrew

From the repository root:

```sh
OPENSSL_PREFIX="$(brew --prefix openssl@3)"
TCL_PREFIX="$(brew --prefix tcl-tk@8)"
./configure --with-tempstore=yes --fts5 --with-tcl="$TCL_PREFIX/lib" --with-tclsh="$TCL_PREFIX/bin/tclsh" CFLAGS="-O2 -DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown -DSQLCIPHER_TEST -I$OPENSSL_PREFIX/include" LDFLAGS="-L$OPENSSL_PREFIX/lib -lcrypto"
make -j2 libsqlite3.a testfixture
make -C textrunsql check
```

`make -C textrunsql all` builds `textrunsql/build/libtextrunsql_pq.a`. Build output is ignored and should not be committed. See [TESTING.md](TESTING.md) for the sanitizer, fuzzer, optimized-object, and clean-clone lanes.

## Minimal flow

Include `textrunsql/include/textrunsql_pq.h`, link the add-on archive, the single SQLCipher archive from this tree, OpenSSL `libcrypto`, and SQLCipher's platform dependencies. The checked public-header consumer in [`test/test_keyspec.c`](test/test_keyspec.c) is the complete minimal example: it generates and imports a recipient, generates and seals a DEK, opens the envelope, opens SQLCipher with explicit flags, applies the recovered DEK, verifies protected content and integrity, and cleans up.

For an existing database, first open with `SQLITE_OPEN_READWRITE` and without `SQLITE_OPEN_CREATE`, open and authenticate the envelope in memory, apply the recovered DEK before schema or page access, then read protected content and run `PRAGMA cipher_integrity_check` and `PRAGMA integrity_check`. Creating a new database is a separate caller-authorized flow that uses `SQLITE_OPEN_CREATE`.

The caller owns exported keys, envelopes, contexts, and DEKs. Wipe private-key encodings and DEKs immediately after their final use. A successful `textrunsql_pq_key_sqlcipher` call sets the SQLCipher key but does not authenticate an existing database.

## Supported boundary

- one ML-KEM-768 recipient;
- recipient key generation and exact public/private import and export;
- cryptographic DEK generation;
- in-memory seal and open bound to a nonempty application context;
- exact 32-byte raw-key handoff to a caller-opened SQLCipher schema; and
- fixed format version 1 and suite 1.

## Outside this boundary

The add-on performs no database, envelope, journal, WAL, directory, or sidecar I/O. It does not implement recipient mutation, multi-recipient selection, DEK rotation or rekey, automatic profile migration, backup orchestration, atomic database-plus-envelope publication, crash recovery, rollback prevention, key custody, password recovery, framework packaging, or application distribution.

The calling product must define durable key custody, atomic publication and backup of the database with its envelope and context metadata, restore verification, incident response, dependency updates, and supported-platform qualification. Independent cryptographic and protocol review, legal/name/export review, delivery-artifact testing, and owner release approval remain required before customer distribution.

Normative details are in [DESIGN.md](DESIGN.md), [FORMAT.md](FORMAT.md), and the public [header](include/textrunsql_pq.h).
