# Update and Rollback System

## Principle

A system update must not mutate the only bootable state in place.

## Reference image layout

~~~
slot A: current known-good
slot B: candidate
recovery: independently bootable
~~~

## Update transaction

1. Fetch candidate metadata.
2. Verify artifact identity and signatures.
3. Verify required proof-package reference.
4. Verify hardware/product compatibility.
5. Stage into inactive slot.
6. Verify staged content hash.
7. Mark trial boot.
8. Boot candidate.
9. Run health criteria.
10. Commit candidate or automatically revert.

## Rollout rings

Reference sequence:
- simulator;
- developer devices;
- internal canary;
- 0.1%;
- 1%;
- 10%;
- 50%;
- 100%.

Promotion is policy-driven, based on deterministic thresholds.

## AI role

Operations AI can analyze rollout health and propose actions. It cannot bypass signatures, rewrite historical health data, suppress rollback thresholds or mark a failed image healthy without an authorized policy change.

## Data migrations

Irreversible migrations are high-risk.

Prefer:
- forward-compatible schemas;
- transitional dual-read/write where practical;
- explicit checkpoints;
- tested downgrade;
- documented human-approved irreversibility when unavoidable.
