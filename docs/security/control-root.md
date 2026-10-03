# Control Root, Rotation and Revocation

## Purpose

ORYVAEL treats privileged control artifacts as signed authority, not as trusted configuration merely because a process can read a JSON file.

The reference control verifier is `oryvael-control`.

It currently protects four artifact classes:
- `tool_catalog`;
- `change_plan`;
- `principal_policy`;
- `workspace_registry`.

The public file-based entrypoints for supervisor, workspace, tool broker, build and proof enforce root-control verification inside their crate boundary. The Trusted Core CLI retains its own checks as defense in depth.

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

## Direct crate boundary

The public file-based APIs of `oryvael-supervisor`, `oryvael-workspace`, `oryvael-tool-broker`, `oryvael-build` and `oryvael-proof` use enforced crate roots. Their historical implementations are private modules, while the public front-door functions perform control verification before entering privileged logic.

An external Rust consumer therefore cannot select the historical unchecked file entrypoint by linking the crate directly.

The Trusted Core CLI still performs its own verification. These duplicate checks are intentional defense in depth rather than the security boundary.

## Verified-byte pinning

A protected pathname is no longer verified and then re-opened by the privileged legacy implementation.

`oryvael-control` now produces a `VerifiedControlArtifact` containing:
- the canonical source path used during acquisition;
- the exact bytes whose SHA-256 and Ed25519 statement were verified;
- the verified signer/root metadata;
- the exact detached signature bytes used for the decision.

The fields that would permit forging such a token are private to the control crate.

Before invoking the private historical implementation, the enforced front door materializes the authenticated bytes into a private snapshot directory. The artifact and signature sidecar are written with create-new semantics and made read-only. The directory itself is made non-writable before consumption.

The private implementation receives only those snapshot paths. It does not receive the original protected pathname.

For request/invocation documents that reference another protected control artifact, the public front door parses the request once, verifies the referenced artifact, rewrites the reference to the pinned snapshot, serializes the normalized request and pins that request as well.

This pattern is applied to:
- supervisor principal policy;
- workspace principal policy, registry and referenced change plan;
- tool-broker principal policy, catalog and referenced change plan;
- build change plan;
- proof change plan, including nested proof-to-build provenance evaluation.

The tool broker also copies its legacy catalog trust/signature sidecars into the same pinned catalog snapshot so the existing internal catalog-verification layer remains active as defense in depth.

## TOCTOU property

Within the intended threat model, replacing or modifying the original protected pathname after verification no longer changes the bytes consumed by the privileged implementation.

A unit test verifies this explicitly:
1. create and sign a control artifact;
2. load it as a verified artifact;
3. replace the original pathname with different bytes;
4. confirm the verified token still exposes the original bytes;
5. confirm verification of the modified original path fails;
6. materialize the verified bytes into a pinned snapshot;
7. confirm that pinned snapshot still verifies against the root policy.

This closes the previously documented verify-path/reopen-same-path race for protected control artifacts.

The snapshot is not claimed to be a kernel-sealed immutable object against arbitrary native code already holding the same trusted host process authority. Such code is already inside the Trusted Computing Base. A future `memfd`/sealed-handle transport can reduce that assumption further and is tracked as defense in depth rather than as the original pathname TOCTOU defect.

## CI evidence

CI creates ephemeral Ed25519 roots and commits no private root key.

The integration path installs:
- key version 1 as revoked;
- key version 2 as active;
- policy epoch 2;
- minimum accepted epoch 2.

It signs the static control fixtures, signs dynamically modified negative-test fixtures when those fixtures are intentionally authorized, and verifies that a valid signature from the revoked v1 key is still rejected.

The `direct_crate_control` integration test bypasses the CLI intentionally and calls the supervisor, workspace, tool-broker, build and proof crates directly with unsigned privileged control artifacts. Every public file-based API must fail closed with a control-verification error.

The complete sandbox/release workflow also runs through the pinned-byte front doors, including Git workspace provisioning, Python/Rust tool brokers, independent verifier evidence, reproducible builds, C2 proof and signed C3 release authorization.

## Remaining hardening

Persistent supervisor/audit services should own root-policy loading, monotonic epoch persistence and verification telemetry rather than relying on per-process file reads.

Additional defense-in-depth work includes:
- sealed `memfd` or equivalent kernel-handle transport for verified control bytes;
- TPM/secure-element backed monotonic epoch state;
- threshold/multi-party authorization for changes to the highest-authority root policy;
- independent recovery-key procedures and root compromise drills.
