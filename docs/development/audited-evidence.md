# Audited Verifier Evidence

## Problem

A proof system is not trustworthy if a producer can write a JSON document saying that tests passed.

ORYVAEL therefore distinguishes declared evidence from evidence derived from an authenticated execution trail.

## Evidence derivation

The reference evidence verifier reads a hash-chained JSONL audit journal and selects one operation ID.

It then requires exactly one Tool Broker run request and exactly one sandbox exit for that operation.

The request must contain:
- broker identity equal to oryvael-tool-broker;
- tool ID;
- tool action;
- verifier role;
- change-plan SHA-256.

The verifier role must be one of:
- test;
- security;
- reviewer.

Developer-role runs are not accepted as verifier evidence.

## Runtime authorization proof

The selected operation must contain exactly one allowed policy decision for:

    resource: tool
    action: execute
    target: <tool>.<action>

The actor identity must remain constant across every audit event associated with the operation.

This prevents evidence extraction from combining records belonging to different principals.

## Result derivation

The status is derived from the audited sandbox exit.

Pass requires:
- audit decision observed;
- exit_code equal to 0;
- timed_out equal to false.

A sandbox exit explicitly recorded as failed produces Fail evidence.

The caller cannot choose Pass or Fail.

## Evidence hash

The evidence verifier serializes all hash-chain-verified audit records belonging to the operation in ledger order and hashes the resulting sequence with SHA-256.

The result therefore commits to:
- request metadata;
- policy decisions;
- sandbox lifecycle;
- output artifact hashes;
- actor;
- change ID;
- operation ID.

## Output

A VerifiedEvidence record contains:
- change_id;
- change_plan_sha256;
- verifier name derived from tool.action;
- principal;
- verifier role;
- derived status;
- evidence_hash;
- operation_id.

The next release-gate step consumes these records and compares their change-plan hash against the exact plan being evaluated.
