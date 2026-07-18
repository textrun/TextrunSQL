# Contributing to TextrunSQL

TextrunSQL keeps its downstream delta small and reviewable. Discuss substantial changes before implementation.

## Scope

Contributions should address the `textrunsql/` add-on, its focused tests, or concise downstream documentation. Changes to inherited SQLite or SQLCipher files require a minimal reproducer, an explanation of why an additive downstream file cannot solve the problem, focused tests, merge-impact analysis, and a removal condition.

Generic SQLCipher fixes should first follow SQLCipher's contribution process, including prior discussion, the requested base branch, and its contributor agreement. Do not mix an upstream candidate with TextrunSQL branding or unrelated downstream changes.

## Provenance

Submit only work you have the right to license under the BSD 3-Clause terms used for downstream-authored files. Do not submit code or documentation copied from commercial, enterprise, FIPS, trial, confidential-support, customer, or otherwise restricted sources.

## Changes

- preserve upstream formatting and authorship;
- avoid generated amalgamations, binaries, frameworks, build output, benchmark reports, and private evidence;
- keep public APIs explicit about lengths, ownership, errors, and thread safety;
- add the smallest permanent regression test for every defect;
- update format documentation and vectors when wire bytes change; and
- keep human-readable prose on one physical line when syntax permits.

All changes must pass the checks in `textrunsql/TESTING.md` from a clean clone.
