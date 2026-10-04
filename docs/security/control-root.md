# Control Root, Rotation and Revocation

## Purpose

ORYVAEL treats privileged control artifacts as signed authority, not as trusted configuration merely because a process can read a JSON file.

The reference control verifier is `oryvael-control`.

It currently protects five artifact classes:
- `tool_catalog`;
- `change_plan`;
- `principal_policy`;
- `workspace_registry`;
- `peer_policy`.

The public file-based entrypoints for supervisor, workspace, tool broker, build and proof enforce root-control verification inside their crate boundary. The persistent trusted service also requires a signed `peer_policy` before it accepts local IPC authority.

## System trust anchor

Production-style execution resolves the root trust policy from:

    /etc/oryvael/root-policy.json

An explicit `ORYVAEL_ROOT_POLICY` override exists for controlled development and test environments.

The root policy contains only public verification material and authorization metadata. Private signing keys are not part of the runtime policy and must not be stored in the repository or an AI-writable workspace.

The persistent `oryvael-service` path loads the root once at service startup, advances the persistent minimum epoch if necessary and pins the exact accepted root-policy bytes for the lifetime of that service instance. A root file edited after startup does not silently change the authority of the running service.

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

`peer_policy` is intentionally a first-class root-authorized kind. Local process-to-principal bindings therefore cannot be edited as ordinary daemon configuration without invalidating the control signature.

## Key rotation

Rotation is additive before it is subtractive:

1. publish a root policy with a new active key version;
2. re-sign authorized control artifacts with the new version;
3. re-sign the local peer policy when its authority changes;
4. verify rollout health;
5. mark the old key version `revoked`;
6. increase the root policy epoch when the trusted state advances;
7. perform a controlled restart of the persistent trusted service so it validates, persists and pins the new root and peer policy.

There is intentionally no unauthenticated remote root-reload operation.

A statement signed with a revoked key is rejected even when its cryptographic signature is mathematically valid.

## Anti-rollback

The reference verifier supports a minimum accepted root-policy epoch.

System default:

    /etc/oryvael/root-policy.min-epoch

Development/test override for direct verifier paths:

    ORYVAEL_ROOT_POLICY_MIN_EPOCH

A root policy whose epoch is below the trusted minimum is rejected. This prevents an attacker from restoring an older policy in which a compromised key was still active.

The persistent trusted service owns the reference file-backed epoch lifecycle: it reads the minimum at startup, rejects rollback and advances a higher epoch using create-new temporary state, file sync, atomic rename and parent-directory sync before accepting requests.

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
- invalid Ed25519 signature;
- missing, malformed or unauthorized signed peer policy at trusted-service startup.

There is no score or warning path for these failures.

## Direct crate boundary

The public file-based APIs of `oryvael-supervisor`, `oryvael-workspace`, `oryvael-tool-broker`, `oryvael-build` and `oryvael-proof` use enforced crate roots. Their historical implementations are private modules, while the public front-door functions perform control verification before entering privileged logic.

An external Rust consumer therefore cannot select the historical unchecked file entrypoint by linking the crate directly.

The Trusted Core CLI still performs its own verification. These duplicate checks are intentional defense in depth rather than the security boundary. High-authority long-lived supervision can instead use `oryvael-service`, which owns a process-lifetime root snapshot, persistent epoch state and signed peer authorization.

## Verified-byte pinning

A protected pathname is no longer verified and then re-opened by the privileged legacy implementation.

`oryvael-control` produces a `VerifiedControlArtifact` containing:
- the canonical source path used during acquisition;
- the exact bytes whose SHA-256 and Ed25519 statement were verified;
- the verified signer/root metadata;
- the exact detached signature bytes used for the decision.

The fields that would permit forging such a token are private to the control crate.

Before invoking a private historical implementation, an enforced front door materializes authenticated bytes into a private snapshot directory. The artifact and signature sidecar are written with create-new semantics and made read-only. The directory itself is made non-writable before consumption.

For request/invocation documents that reference another protected control artifact, the public front door parses the request once, verifies the referenced artifact, rewrites the reference to the pinned snapshot, serializes the normalized request and pins that request as well.

This pattern is applied to:
- supervisor principal policy;
- workspace principal policy, registry and referenced change plan;
- tool-broker principal policy, catalog and referenced change plan;
- build change plan;
- proof change plan, including nested proof-to-build provenance evaluation.

The persistent service applies the same principle to governance state: root-policy bytes are pinned once, and `peer_policy` is parsed from the exact bytes verified against that pinned root.

## IPC authority binding

The signed peer policy links kernel-authenticated local process identity to service authority. On Linux the service obtains PID/UID/GID from `SO_PEERCRED`, resolves and hashes `/proc/<pid>/exe`, then requires an exact signed peer binding for UID, GID and executable SHA-256.

That binding separately limits service operations and, for `supervise`, the ORYVAEL principal IDs the process may claim. Possession of a valid signed principal policy alone is therefore insufficient to impersonate that principal through the persistent service.

The trust sequence is:

    root-authorized peer policy
        -> kernel process identity
        -> permitted service operation
        -> root-authorized principal policy
        -> exact peer/principal binding
        -> capability/policy enforcement

## TOCTOU property

Within the intended threat model, replacing or modifying the original protected pathname after verification no longer changes the bytes consumed by the privileged implementation.

Control tests verify source replacement after verification does not alter the pinned authenticated bytes. Trusted-service tests separately verify that replacing the root-policy file while a service is running does not change that instance's verification authority; a controlled restart then applies the new root state.

The snapshot is not claimed to be a kernel-sealed immutable object against arbitrary native code already holding the same trusted host process authority. Such code is already inside the Trusted Computing Base. A future `memfd`/sealed-handle transport can reduce that assumption further.

For IPC identity, current executable hashing uses `/proc/<pid>/exe` after `SO_PEERCRED`. A future pidfd-backed identity path is tracked as additional defense against process-lifecycle races.

## CI evidence

CI creates ephemeral Ed25519 roots and commits no private root key.

The integration path installs:
- key version 1 as revoked;
- key version 2 as active;
- policy epoch 2;
- minimum accepted epoch 2;
- `peer_policy` as an authorized root control kind.

It signs static control fixtures, signs dynamically modified negative-test fixtures when intentionally authorized, and verifies that a valid signature from the revoked v1 key is still rejected.

The `direct_crate_control` integration test bypasses the CLI intentionally and requires unsigned privileged control artifacts to fail closed at public crate boundaries.

Trusted-service tests exercise restart-persistent epoch state, rollback rejection, `SO_PEERCRED`, signed peer authorization, unbound-peer rejection, principal spoof rejection, service audit attribution and process-lifetime pinned-root behavior.

The complete sandbox/release workflow also runs through the pinned-byte front doors, including Git workspace provisioning, Python/Rust tool brokers, independent verifier evidence, reproducible builds, C2 proof and signed C3 release authorization.

## Remaining hardening

Root ownership, file-backed monotonic epoch persistence and kernel-authenticated local peer/principal binding are now implemented in the persistent Trusted Supervisor/Audit Service.

Additional defense-in-depth work includes:
- pidfd-backed peer executable identity and process-lifecycle hardening;
- migration of remaining component journals into authenticated single-owner audit ingestion plus external checkpoints;
- sealed `memfd` or equivalent kernel-handle transport for verified control bytes;
- TPM/secure-element backed monotonic epoch state;
- threshold/multi-party authorization for the highest-authority root policy;
- independent recovery-key procedures and root compromise drills.
