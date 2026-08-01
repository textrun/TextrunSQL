# Envelope format version 1

This document is normative for TextrunSQL envelope format version 1, suite 1. An envelope is exactly 1236 bytes. Multi-byte integers are unsigned big-endian. Every field has one accepted encoding; trailing bytes, omitted bytes, nonzero reserved bits, and mismatched declared lengths are invalid.

## Fields

| Offset | Length | Field | Required value or meaning |
| ---: | ---: | --- | --- |
| 0 | 8 | magic | ASCII `TRSQLPQ` followed by `00` |
| 8 | 2 | format version | `0001` |
| 10 | 2 | suite | `0001` |
| 12 | 2 | flags | `0000` |
| 14 | 2 | reserved | `0000` |
| 16 | 4 | total length | `000004d4` (1236) |
| 20 | 2 | KEM ciphertext length | `0440` (1088) |
| 22 | 2 | wrapped DEK length | `0020` (32) |
| 24 | 32 | recipient identifier | SHA-256 of the exact 1184-byte ML-KEM-768 public-key encoding |
| 56 | 32 | context hash | SHA-256 of the caller's context bytes |
| 88 | 1088 | KEM ciphertext | ML-KEM-768 encapsulation ciphertext |
| 1176 | 12 | nonce | random AES-GCM nonce |
| 1188 | 32 | wrapped DEK | AES-256-GCM ciphertext |
| 1220 | 16 | tag | AES-256-GCM authentication tag |

The context is a nonempty byte string of 1 through 1024 bytes. Its syntax and stable mapping to one database are application-defined. A product must use an identifier that cannot be ambiguously re-encoded or reassigned.

## Suite 1

- KEM: ML-KEM-768 as standardized by NIST FIPS 203;
- KEM public key: 1184 bytes;
- KEM private key: 2400 bytes in the OpenSSL raw private-key encoding accepted by this API;
- KEM ciphertext: 1088 bytes;
- KEM shared secret: 32 bytes;
- hashes: SHA-256;
- KDF: HKDF-SHA-256;
- KDF input key material: the ML-KEM shared secret;
- KDF salt: the 32-byte context hash;
- KDF info: UTF-8 bytes of `TextrunSQL/PQEnvelope/v1/ML-KEM-768/HKDF-SHA-256/AES-256-GCM`;
- AEAD: AES-256-GCM;
- nonce: 12 random bytes;
- plaintext: exactly the 32-byte DEK; and
- associated data: envelope bytes 0 through 1187 inclusive.

The associated data therefore covers the canonical header, declared lengths, recipient identifier, context hash, ML-KEM ciphertext, and nonce. The domain-specific magic and KDF info prevent this construction from being interpreted as another protocol.

## Parsing and errors

A reader first verifies the exact input length and fixed structural values. Unknown format versions or suites return the unsupported class. Invalid magic, flags, reserved bytes, total length, component lengths, truncation, or trailing data return the format class. Recipient mismatch, context mismatch, KEM failure, or AEAD failure return the authentication class at the public open boundary. A reader never releases candidate plaintext before authentication succeeds.

There is no negotiation, fallback, compression, extension field, alternate serialization, password mode, recipient probing, or optional value. The fixed-size grammar requires no parser allocation.

## Vectors and migration

Files in [vectors](vectors/) are hexadecimal or `name=value` text. [vectors/README.md](vectors/README.md) records their source, revision, producer, hashes, public synthetic-secret status, and reproduction commands.

Format version 1 has an exact byte definition. A future incompatible definition must use a new format or suite identifier. Readers must reject unknown identifiers; they must never reinterpret version 1 bytes under a changed algorithm. A migration tool requires independent design, failure-recovery tests, and an explicit release decision before use.
