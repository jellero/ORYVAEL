# Control Root, Rotation and Revocation

## Purpose

ORYVAEL treats privileged control artifacts as signed authority, not as trusted configuration merely because a process can read a JSON file.

The reference control verifier is `oryvael-control`.

It currently protects four artifact classes:
- `tool_catalog`;
- `change_plan`;
- `principal_policy`;
- `workspace_registry`.

The official Trusted Core CLI verifies these artifacts before entering privileged supervisor, workspace, tool, build, proof or release flows.

## System trust anchor

Production-style execution resolves the root trust policy from:

    /etc/oryvael/root-policy.json

An explicit `ORYVAEL_ROOT_POLICY` override exists for controlled development and test environments.

The root policy contains only public verification material and authorization metadata. Private signing keys are not part of the runtime policy and must not be stored in the repository or an AI-writable workspace.

## Signed artifact statement

Every protected artifact has a detached sidecar:

    <artifact>.control.json

The Ed25519 signature uses the domain:

    ORYVAEL-CONTROL-V1

and binds:
- artifact kind;
- signer ID;
- key version;
- SHA-256 of the exact artifact bytes.

Changing any protected artifact byte invalidates the statement.

## Root policy

A root signer entry declares:
- stable signer ID;
- monotonic key version;
- Ed25519 public key;
- `active` or `revoked` status;
- the artifact kinds that key is permitted to authorize.

Signer identity is therefore the tuple `(id, key_version)`, not only a human-readable name.

## Key rotation

Rotation is additive before it is subtractive:

1. publish a root policy with a new active key version;
2. re-sign authorized control artifacts with the new version;
3. verify rollout health;
4. mark the old key version `revoked`;
5. increase the root policy epoch when the trusted state advances.

A statement signed with a revoked key is rejected even when its cryptographic signature is mathematically valid.

## Anti-rollback

The reference verifier supports a minimum accepted root-policy epoch.

System default:

    /etc/oryvael/root-policy.min-epoch

Development/test override:

    ORYVAEL_ROOT_POLICY_MIN_EPOCH

A root policy whose epoch is below the trusted minimum is rejected. This prevents an attacker from restoring an older policy in which a compromised key was still active.

The minimum epoch must be stored in a location whose integrity is at least as strong as the root policy. A production implementation should place this state in TPM/secure-element backed storage or another monotonic trusted-state mechanism where available.

## Fail-closed behavior

Privileged execution rejects:
- missing root policy;
- unsupported policy/signature versions;
- stale policy epoch;
- unknown signer/version;
- revoked signer/version;
- signer not authorized for the artifact kind;
- artifact hash mismatch;
- malformed public key/signature;
- invalid Ed25519 signature.

There is no score or warning path for these failures.

## CI evidence

CI creates ephemeral Ed25519 roots and commits no private root key.

The integration path installs:
- key version 1 as revoked;
- key version 2 as active;
- policy epoch 2;
- minimum accepted epoch 2.

It signs the static control fixtures, signs dynamically modified negative-test fixtures when those fixtures are intentionally authorized, and verifies that a valid signature from the revoked v1 key is still rejected.

## Current boundary and next hardening

The operational reference path is fail-closed at the Trusted CLI boundary and the control verifier is a Trusted Core crate available to supervisor/build/proof/workspace/tool components.

The next hardening step is to invoke the verifier inside every file-based crate API as well, so embedding a library directly cannot bypass the same root policy. Persistent supervisor/audit services should then own root-policy loading, epoch persistence and verification telemetry rather than relying on per-process file reads.
