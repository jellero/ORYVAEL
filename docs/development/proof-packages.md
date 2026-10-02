# Proof Packages and Release Eligibility

## Purpose

A proof package is the deterministic handoff between implementation/verification and release policy.

It is not an AI confidence score. It is a structured set of evidence that can be checked without asking the model that produced the code whether its own work is safe.

## Inputs

The current audited reference engine consumes:
- the immutable change plan;
- source repository/commit/tree identity;
- verifier audit-log and operation references;
- release artifact hashes;
- deterministic build-manifest input;
- an independent build-manifest input when build:reproducible is requested.

Verifier results are derived from the verified audit chain.

## Deterministic rules

The reference engine applies fail-closed rules including:
1. source repository and commit must be non-empty;
2. non-C0 changes need at least one artifact;
3. artifact and evidence hashes must be SHA-256-shaped values;
4. any verifier failure vetoes eligibility;
5. every verifier named in the change plan must have passing evidence;
6. C2/C3/C4 required evidence must include a passing verifier whose principal differs from the producer;
7. C3/C4 require independent security-role evidence;
8. C4 requires independent reviewer-role evidence;
9. release-grade C2/C3/C4 audited proofs require deterministic build provenance;
10. build:reproducible requires an independent builder whose build matches source, toolchain, build command, Cargo.lock identity, SBOM and artifact hashes.

The output records every unmet rule in eligibility_reasons.

## Build provenance

The proof engine does not trust a serialized build-manifest claim. It regenerates the manifest from the supplied build input and hashes the declared artifacts directly.

The proof records:
- build manifest SHA-256;
- SBOM SHA-256;
- Cargo.lock SHA-256;
- reproducible-build status;
- independent builder identity and second manifest hash when required.

A divergent independent artifact vetoes the proof.

## Separation of duties

For elevated changes, producer and verifier identities are compared as data, not inferred from prompts.

A verifier result produced by the implementation principal cannot satisfy the independent-verifier requirement for C2+.

## Veto semantics

A failure is never averaged against successful checks.

If a mandatory verifier fails, build provenance diverges, or required provenance is missing, the candidate is ineligible.

## Human approvals

The technical proof package intentionally does not grant human release authority.

For C3/C4, the release gate constructs the exact release context and verifies signed approvals against the configured trust policy. Approval signatures are bound to the change-plan hash, proof hash, artifact hash and rollout ring.

## CLI

Build an audited proof package:

    oryvael proof-build-audited --plan change-plan.json --input audited-proof-input.json

Exit code 0 means the package is eligible.

Exit code 4 means the package was built but is ineligible.

Other non-zero codes indicate invalid input or evidence/provenance verification failure.
