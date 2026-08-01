# Testing

Run commands from the repository root after the SQLCipher configure command in [README.md](README.md).

## Focused checks

```sh
make libsqlite3.a testfixture
./testfixture test/sqlcipher.test
make -C textrunsql check
```

The inherited SQLCipher suite exercises the selected unmodified baseline. `make check` runs the C envelope and ACVP vector tests, the public-header consumer and exact-DEK SQLCipher test, and the focused Tcl compatibility suite.

The tests cover key generation/import/export, key-pair mismatch rejection, format version and suite rejection, exact and incorrect component lengths, every truncation length, trailing data, every single-bit envelope corruption, wrong context, wrong recipient, authentication failure, allocation/provider/random failure injection, maximum context boundaries, deterministic vectors, no-create opening, wrong SQLCipher key, raw-key versus passphrase behavior, leading and trailing zero bytes, and all 256 byte values across exact 32-byte DEKs.

## Sanitizers and fuzz smoke

```sh
make -C textrunsql asan
make -C textrunsql fuzz-smoke
```

`asan` rebuilds the focused C tests and public consumer with AddressSanitizer and UndefinedBehaviorSanitizer. `fuzz-smoke` uses a libFuzzer-capable Clang, generates a binary seed from the tracked version-1 vector under the ignored build directory, loads the small format dictionary, and runs 5,000 parser executions. On macOS, the Makefile selects Homebrew LLVM when available because Apple Clang does not ship the libFuzzer runtime. The `macos-15` GitHub-hosted lane uses the image's Homebrew LLVM 18 compiler, which is compatible with that image's Xcode 16 linker.

## Optimized object checks

```sh
make -C textrunsql all
nm textrunsql/build/libtextrunsql_pq.a | grep textrunsql_pq_test && exit 1 || true
nm textrunsql/build/libtextrunsql_pq.a | grep textrunsql_test_fail && exit 1 || true
nm -u textrunsql/build/test_keyspec | grep ' _sqlite3_' | sort -u
otool -L textrunsql/build/test_keyspec
```

On ELF systems use `readelf -d` or `ldd` instead of `otool`. The production archive must contain no deterministic test or fault-injection symbol. The consumer links the one SQLCipher archive built from this repository; it must not link another SQLite library.

Object disassembly must retain calls or relocations to `OPENSSL_cleanse` from the envelope, provider, and keyspec objects. The final qualification also scans logs and tracked files for machine-local paths, credentials, generated outputs, and synthetic secrets outside the documented public vectors.

## What these checks establish

The suite establishes exact behavior for the tested commit, OpenSSL provider, compiler, operating system, architecture, and flags. NIST sample agreement establishes exact tested ML-KEM inputs and outputs. It does not establish side-channel resistance, a validated cryptographic module, safe product lifecycle, every OpenSSL provider configuration, or every platform.

Before distributing a delivery artifact, qualify it on every supported platform and compiler, complete independent cryptographic and protocol review, test product-owned custody/backup/recovery/atomic-publication behavior, and repeat the security and dependency review.
