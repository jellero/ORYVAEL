# Deterministic Release Gate

## Purpose

The Release Gate decides whether an artifact may advance to a rollout ring.

It does not trust a previously serialized proof-package JSON. Instead it receives:
- the exact change plan;
- an audited-proof input containing journal/operation references;
- an artifact name;
- the actual artifact file;
- the requested rollout ring.

It rebuilds the audited proof internally.

## Checks

The current reference gate requires:
- proof change ID equals the plan ID;
- proof change class equals the plan class;
- audited proof is eligible;
- evidence_verified is true;
- proof is bound to a change-plan SHA-256;
- exactly one proof artifact has the requested artifact name;
- the SHA-256 of the actual artifact file equals the proof artifact hash;
- requested rollout ring does not exceed the plan maximum.

A failure produces an ineligible decision with explicit reasons.

## Rollout order

The reference ordering is:

    none < simulator < developer < canary < fleet

A plan capped at canary cannot request fleet.

## C3 and C4

C3 and C4 releases are currently denied even if the structural proof contains a human approval reference.

Reason: a plain string is not an authorization credential.

The gate remains fail-closed until ORYVAEL has signed human-approval objects bound to:
- human identity;
- change-plan hash;
- proof hash;
- artifact hash;
- permitted rollout scope.

## Artifact integrity

The artifact hash is calculated by the release gate from the file itself.

Changing one byte after proof construction makes the candidate ineligible.

## CLI

    oryvael release-check \
      --plan change-plan.json \
      --input audited-proof-input.json \
      --artifact-name system.img \
      --artifact ./system.img \
      --ring canary

Exit code 0 means eligible.

Exit code 5 means a deterministic release decision was produced but is ineligible.

Other non-zero codes indicate invalid input or failure to verify required evidence.
