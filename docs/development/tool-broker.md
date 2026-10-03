# Capability-Bound Tool Broker

## Purpose

The Tool Broker turns development tools into named, policy-addressable operations rather than giving an AI a privileged shell.

An invocation identifies:
- principal;
- role;
- change ID;
- external change plan;
- workspace;
- tool;
- named action;
- audit and artifact destinations.

The AI does not supply an executable path or arbitrary argv. Those come from a trusted tool catalog.

## Signed catalog root

A catalog is no longer trusted merely because its SHA-256 is recorded in the audit log.

For a catalog named `catalog.json`, the broker requires two external control artifacts beside it:

    catalog.trust.json
    catalog.signature.json

The trust policy contains authorized Ed25519 public keys. The signature statement contains:
- version;
- signer ID;
- SHA-256 of the exact catalog bytes;
- Ed25519 signature.

The signed payload is domain-separated as:

    ORYVAEL-TOOL-CATALOG-V1 || 0x00 || signer_id || 0x00 || catalog_sha256

The broker verifies, before resolving any tool or action:
1. supported trust-policy version;
2. supported signature version;
3. unique signer IDs in the trust policy;
4. exact SHA-256 match against the catalog bytes on disk;
5. signer presence in the trust policy;
6. Ed25519 public-key and signature structure;
7. cryptographic signature validity.

Any failure is fail-closed and the sandbox is never started.

The trust policy, signature statement, catalog, invocation, principal policy and change plan must all live outside the writable worker workspace.

The reference repository contains a public reference root used only to exercise the mechanism. Production deployments must provision their own offline/root-controlled catalog key material; private catalog signing keys are not committed to the repository.

## Authorization model

A developer action executes only when four independent conditions agree:
1. a trusted signer has authorized the exact tool catalog bytes;
2. the catalog maps the tool/action name to a concrete executable and fixed argv;
3. the change plan requests that exact tool capability;
4. principal policy grants both process execution and tool execution.

Verifier roles use the same signed catalog, but their action must appear in the plan verification list and their principal must differ from the producer.

The supervisor performs the final capability checks.

## Change-plan and audit binding

Before execution the broker hashes:
- principal policy;
- tool catalog;
- catalog trust policy;
- catalog signature statement;
- tool invocation;
- change plan.

The audit context records:
- tool catalog SHA-256;
- catalog signer ID;
- trust-policy SHA-256;
- signature-statement SHA-256;
- invocation SHA-256;
- principal-policy SHA-256;
- change-plan SHA-256.

This allows later evidence to establish not only which catalog was used, but which root-authorized signer approved it.

The invocation change_id must exactly match the parsed plan ID.

For role developer, the invoking principal must equal the plan producer.

For roles test, security and reviewer, the principal must differ from the producer. The selected action must be present in the plan verification list.

This creates an enforceable separation-of-duties primitive rather than treating reviewer/test roles as labels.

## No arbitrary command channel

The broker intentionally has no user-provided trailing argument list.

Every action has fixed argv in the catalog. Structured parameters may be added later only with explicit normalization and validation; they must not be concatenated into a shell command.

No shell is used by the broker.

## Rust profiles

The reference catalog exposes:
- rust.check: cargo check --locked --offline --all-targets;
- rust.test: cargo test --locked --offline --all-targets;
- rust.fuzz-smoke: cargo test --locked --offline --test fuzz_smoke -- --nocapture.

The Rust toolchain is mounted read-only at:

    /opt/oryvael/toolchains/rust

and that toolchain bin directory is the only non-system addition to the supervisor safe PATH.

The example C2 flow attributes rust.check to Developer AI, rust.test to Test AI and rust.fuzz-smoke to Security AI. Test and Security evidence is derived from the supervisor audit journal, not supplied as a self-asserted result.

The fuzz-smoke action is a bounded deterministic seed sweep. It verifies the broker path and security-role attribution, but it is not a substitute for coverage-guided libFuzzer/cargo-fuzz. A coverage-guided backend remains a Phase 2 hardening target.

## Security layers

A brokered action executes through:

    signed catalog + trust policy
        |
    signature verification
        |
    tool invocation
        |
    plan/catalog binding
        |
    tool.execute policy check
        |
    process.execute policy check
        |
    namespace + mount sandbox
        |
    fixed executable + argv
        |
    audit + content-addressed output

Network and additional host paths remain controlled by the signed catalog action and then independently authorized by supervisor policy.

Rust actions deny network and can read only the explicitly authorized toolchain mount in addition to the normal sandbox runtime.

## Current limitations

The reference trust policy is a static local file. A production ORYVAEL deployment still needs secure provisioning, rotation, revocation and recovery procedures for catalog-signing roots.

The current signature model is single-signature authorization. Threshold/multi-party catalog authorization can be added for especially sensitive system catalogs.

Git mutation remains in the dedicated Workspace Broker rather than being exposed as a generic writable Git tool action.

The current fuzz-smoke profile is deterministic and bounded; coverage-guided fuzzing is not yet implemented.
