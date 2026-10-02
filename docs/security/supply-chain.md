# Software Supply Chain

## Release identity

Every privileged artifact should identify:
- source commit;
- repository;
- toolchain;
- dependency lock;
- dependency hashes where supported;
- build environment;
- recipe;
- output hashes;
- SBOM;
- proof package;
- signer.

## Trusted Core policy

Preference order:
1. standard library;
2. small audited dependency;
3. narrow internal implementation;
4. large framework only with an explicit ADR.

AI SDKs, document parsers and provider clients are forbidden in Trusted Core by default.

## Registries

Package registries are external trust domains. Release builds should use locked versions, hash verification and preferably mirrored immutable artifacts.

## Reproducibility

System artifacts target byte-for-byte reproducibility. Until achieved, the proof package records non-deterministic inputs explicitly.

## Dependency retirement

Dependency AI continuously identifies unused, duplicate, abandoned, vulnerable, privilege-expanding and transitive-explosion dependencies.
