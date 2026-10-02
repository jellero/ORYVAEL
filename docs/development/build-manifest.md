# Build Manifest and SBOM

ORYVAEL separates build execution from build attestation.

The build worker may compile software inside an isolated environment. The oryvael-build component does not execute compilers and does not need build-host privilege. It deterministically records what was built after the artifacts exist.

## Binding

Generation requires a change plan containing build:manifest.

The manifest binds:
- SHA-256 of the exact change-plan bytes;
- SHA-256 of the committed Cargo.lock;
- normalized dependency graph derived from cargo metadata --locked;
- builder principal;
- source repository/commit/tree;
- toolchain identity;
- target and profile;
- declared build command;
- artifact hashes and byte lengths.

## No AI-declared SBOM

Dependency components are not accepted as a free-form list from an AI or build request.

The caller provides:
- the committed Cargo.lock;
- JSON emitted by cargo metadata --locked --format-version 1.

oryvael-build derives the normalized SBOM from that resolver output.

## Path normalization

Raw Cargo metadata contains host-local paths and Cargo package IDs for workspace crates may contain filesystem locations.

ORYVAEL converts each package to a stable logical ID:
- workspace packages: workspace:<name>@<version>;
- external packages: cargo:<name>@<version>#<resolved-source>.

Dependency edges are rewritten to those IDs and sorted.

Artifact input paths are used only to open and hash files. They are not part of normalized_input_sha256 or manifest_sha256.

Two builders with identical logical inputs and identical artifact bytes therefore produce the same build-manifest identity even if their work directories differ.

## Artifact evidence

Each declared artifact is opened by the manifest generator and hashed directly. An AI-provided artifact hash is never accepted as authoritative input.

Recorded fields are:
- logical artifact name;
- SHA-256;
- byte length.

## Toolchain identity

The manifest records toolchain name/version and optionally a SHA-256 for a pinned toolchain bundle.

Production workers should use content-addressed toolchain images or immutable toolchain roots. Merely writing a version string into an input file is not sufficient provenance; later build-worker evidence will bind the observed toolchain identity.

## SBOM

The internal format is oryvael-sbom/2.

Each component records:
- stable ID;
- name;
- exact resolved version;
- source;
- optional license;
- optional registry checksum;
- workspace/external classification;
- sorted direct dependency edges.

This is ORYVAEL's deterministic internal representation, not a claim of CycloneDX or SPDX compliance. Standards exporters should remain outside the release-authorization TCB.

## Reproducible-build contract

A reproducibility verifier runs the same locked recipe in independent clean workers.

Equal manifest inputs are necessary but not sufficient. The strong reproducibility condition is:

    builder A artifact SHA-256 == builder B artifact SHA-256

That comparison becomes independent verifier evidence and can then be required by proof/release policy.

## CLI

Generate metadata with locked resolution:

    cargo metadata --locked --format-version 1 > /tmp/oryvael-build-metadata.json

Create the declared artifact and run:

    oryvael build-manifest \
      --plan examples/build/c1-plan.json \
      --input examples/build/input.json

The returned manifest_sha256, cargo_lock_sha256, sbom.sha256 and artifact hashes are provenance inputs for proof and release.
