# Upstream provenance

TextrunSQL preserves the full SQLCipher Git history and adds a small downstream commit stack.

## Frozen baseline

- Upstream: `https://github.com/sqlcipher/sqlcipher.git`
- SQLCipher release: `v4.17.0`
- Commit: `810db22f575ee7cf94ea96a3e91622b5fcece3dc`
- SQLite version: `3.53.3`
- SQLite Fossil manifest: `d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62`

The `v4.17.0` annotated tag has a valid signature from key `2646E8ECC00DAF4C2F67DBCD19A0457D05EA8350`. The local verification environment did not independently certify the signer's identity in its trust database, so the signature result is recorded as cryptographically valid with unknown local owner trust.

## Remote policy

The local `upstream` remote fetches from the official SQLCipher GitHub repository. Its push URL is `DISABLED`. Downstream publication uses a separate `origin` only after the exact candidate has passed qualification.

## Updating

1. Fetch upstream read-only.
2. Verify the selected tag, commit, SQLite version, manifest, and license changes.
3. Rebase or merge in a dedicated update branch.
4. Run the unmodified SQLCipher suite before applying downstream tests.
5. Review every inherited-file conflict manually.
6. Re-run the complete TextrunSQL qualification matrix.

TextrunSQL-specific product files are not proposed as upstream SQLCipher changes. Independently useful SQLCipher fixes should be discussed with SQLCipher maintainers first and prepared against the branch they request.
