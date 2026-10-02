# Build Manifest and SBOM

ORYVAEL separates build execution from build attestation.

The build worker may compile software inside an isolated environment. The oryvael-build component does not execute compilers and does not need build-host privilege. It deterministically records what was built after the artifacts exist.

## Binding

Generation requires a change plan containing build:manifest. The output contains SHA-256 of the exact change-plan bytes and the exact manifest-input bytes.

## Artifact evidence

Each declared artifact is opened by the manifest generator and hashed directly. An AI-provided artifact hash is never accepted as authoritative input.

Recorded fields are logical artifact name, SHA-256 and byte length.

## Toolchain identity

The manifest records name, version and optionally a SHA-256 for a pinned toolchain bundle. Production workers should use content-addressed toolchain images or immutable toolchain roots.

## SBOM

The current internal format is oryvael-sbom/1. Each component records name, version, source and optional SHA-256 checksum. Components are sorted canonically before hashing.

This is an ORYVAEL internal format, not a claim of CycloneDX or SPDX compliance.

## Reproducible-build contract

A reproducible worker runs the same change from identical source, toolchain, dependency inventory, target/profile and isolated environment. Independent workers are expected to produce the same artifact hash; that comparison becomes verifier evidence.

## CLI

Create the declared artifact and run:

    oryvael build-manifest --plan examples/build/c1-plan.json --input examples/build/input.json

The returned manifest_sha256, sbom.sha256 and artifact hashes are inputs to later proof and provenance stages.
