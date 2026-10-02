# Deterministic Release Gate

## Purpose

The Release Gate decides whether an artifact may advance to a rollout ring.

It does not trust a previously serialized proof-package JSON. Instead it receives:
- the exact change plan;
- an audited-proof input containing journal/operation and build-provenance references;
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
- required build provenance and reproducibility checks have already passed inside the rebuilt proof;
- exactly one proof artifact has the requested artifact name;
- the SHA-256 of the actual artifact file equals the proof artifact hash;
- requested rollout ring does not exceed the plan maximum.

A failure produces an ineligible decision with explicit reasons.

## Rollout order

The reference ordering is:

    none < simulator < developer < canary < fleet

A plan capped at canary cannot request fleet.

## C3 and C4 approvals

Critical releases remain fail-closed without cryptographically verified human approval.

The gate creates an approval context bound to:
- change ID and class;
- change-plan SHA-256;
- rebuilt proof SHA-256;
- artifact name and SHA-256;
- requested rollout ring.

Approval signatures are verified against an external trust policy containing authorized signer public keys, permitted change classes and policy-defined thresholds.

A signature created for a different artifact, proof, plan or rollout context does not authorize the release.

## Artifact integrity

The artifact hash is calculated by the release gate from the file itself.

Changing one byte after proof construction makes the candidate ineligible. For signed C3/C4 releases, the changed artifact also changes the approval context, so the previous approval no longer satisfies the threshold.

## CLI

    oryvael release-check \
      --plan change-plan.json \
      --input audited-proof-input.json \
      --artifact-name system.img \
      --artifact ./system.img \
      --ring canary

For C3/C4, also provide the approval policy and approval bundle.

Exit code 0 means eligible.

Exit code 5 means a deterministic release decision was produced but is ineligible.

Other non-zero codes indicate invalid input or failure to verify required evidence/provenance.
