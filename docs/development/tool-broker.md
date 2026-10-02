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

The AI does not supply an executable path or arbitrary argv. Those come from an administrator-controlled tool catalog.

## Authorization model

A developer action executes only when three independent conditions agree:
1. the trusted catalog maps the tool/action name to a concrete executable and fixed argv;
2. the change plan requests that exact tool capability;
3. principal policy grants both process execution and tool execution.

Verifier roles use the same catalog, but their action must appear in the plan verification list and their principal must differ from the producer.

The supervisor performs the final capability checks.

## Change-plan binding

Before execution the broker hashes:
- principal policy;
- tool catalog;
- tool invocation;
- change plan.

Those hashes are passed as namespaced audit context to the supervisor.

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

A brokered action still executes through the Phase 1 supervisor:

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

Network and additional host paths remain controlled by the catalog action and then independently authorized by supervisor policy.

Rust actions deny network and can read only the explicitly authorized toolchain mount in addition to the normal sandbox runtime.

## Current limitations

The catalog is hashed and audit-bound but not yet signed by a constitutional/trusted catalog key.

The next hardening step is a signed catalog/provenance model so a compromised ordinary system service cannot redefine a privileged action without producing an invalid authorization artifact.

Git mutation remains in the dedicated Workspace Broker rather than being exposed as a generic writable Git tool action.

The current fuzz-smoke profile is deterministic and bounded; coverage-guided fuzzing is not yet implemented.
