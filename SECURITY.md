# Security policy

## Reporting

Report suspected vulnerabilities through GitHub private vulnerability reporting for this repository. If that feature is unavailable, contact the repository owner through an established confidential channel before sending sensitive details.

Do not include live database keys, private recipient keys, sensitive data, credentials, or production database files in a report. Use synthetic reproductions.

## Scope

TextrunSQL security reports include:

- envelope parsing, canonicality, authentication, or context binding;
- ML-KEM key import, generation, encapsulation, or decapsulation;
- key-derivation and AEAD composition;
- secret lifetime, disclosure, or logging;
- exact database-key handoff to SQLCipher; and
- build or dependency behavior that changes the documented security contract.

SQLCipher defects that reproduce without TextrunSQL should be reported through SQLCipher's documented process. SQLite defects should follow SQLite's reporting process.

## Response

Reports are acknowledged confidentially, reproduced with synthetic inputs, assigned a severity and affected-version range, and resolved before disclosure. Disclosure timing is coordinated with affected reporters and upstream projects when their code is involved.

No security certification, FIPS validation, or third-party audit is implied by this policy.
