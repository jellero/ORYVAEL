# Proof Packages and Release Eligibility

## Purpose

A proof package is the deterministic handoff between implementation/verification and release policy.

It is not an AI confidence score. It is a structured set of references that can be checked without asking the model that produced the code whether its own work is safe.

## Inputs

The current reference engine consumes:

- the immutable change plan;
- source repository/commit/tree identity;
- verifier results;
- verifier principal identities;
- verifier operation IDs;
- evidence hashes;
- release artifact hashes;
- human approval references where required.

Each verifier result is one of pass, fail or skipped.

## Deterministic rules

The reference engine currently applies these rules:

1. source repository and commit must be non-empty;
2. non-C0 changes need at least one artifact;
3. artifact and evidence hashes must be SHA-256-shaped values;
4. any verifier with status fail vetoes eligibility;
5. every verifier named in the change plan must have passing evidence;
6. C2/C3/C4 required evidence must include a passing verifier whose principal differs from the producer;
7. C3/C4 need at least one non-empty human approval reference.

The output records every unmet rule in eligibility_reasons.

## Separation of duties

For elevated changes, producer identity and verifier identity are compared as data, not inferred from model prompts.

Example:

    producer: developer-ai/42
    verification:
      - test
      - security

A test result from developer-ai/42 does not satisfy the independent verifier rule for C2+.

A result from test-ai/17 can satisfy it if the evidence is otherwise valid.

## Veto semantics

A failure is not averaged against successful checks.

If security reports fail while build and tests report pass, the candidate is ineligible.

This prevents a score-based system from converting a mandatory security failure into an acceptable average.

## Human approvals

The current alpha treats a human approval as an external reference string and only checks that one exists when C3/C4 require it.

This is intentionally documented as incomplete.

The production release gate must verify signed approval objects against authorized human identities and the exact proof/change hashes. A text reference alone must never become a production authorization credential.

## CLI

Build an eligible C2 proof package:

    cargo run -p oryvael-cli -- proof-build       --plan examples/proof/c2-plan.json       --evidence examples/proof/c2-evidence.json

The command prints the package as JSON.

Exit codes:
- 0: package is eligible;
- 4: package was built but is ineligible;
- other non-zero: input or execution error.

This makes eligibility usable directly as a CI/release gate.
