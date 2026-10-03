# Capability-Bound Tool Broker

## Purpose

The Tool Broker turns development tools into named, policy-addressable operations rather than giving an AI a privileged shell.

An invocation identifies:
- principal;
- role;
- change ID;
- external change plan;
- catalog trust policy and signature bundle;
- workspace;
- tool;
- named action;
- audit and artifact destinations.

The AI does not supply an executable path or arbitrary argv. Those come from a signed administrator-controlled tool catalog.

## Authorization model

A developer action executes only when four independent conditions agree:
1. the catalog bytes satisfy the configured root-trust signature threshold for purpose `tool_catalog`;
2. the trusted catalog maps the tool/action name to a concrete executable and fixed argv;
3. the change plan requests that exact tool capability;
4. principal policy grants both process execution and tool execution.

Verifier roles use the same signed catalog, but their action must appear in the plan verification list and their principal must differ from the producer.

The supervisor performs the final capability checks.

## Signed catalog root trust

The broker verifies the catalog before deserializing or resolving an action.

The reference trust format uses Ed25519 signatures over a domain-separated canonical message containing:
- control-artifact protocol version;
- purpose (`tool_catalog`);
- signer identity;
- SHA-256 of the exact catalog bytes.

The trust policy declares authorized public keys, their allowed control-artifact purposes and a per-purpose signature threshold. A missing or zero threshold is fail-closed.

The signature is byte-exact. Reformatting the JSON, adding whitespace or changing a single action changes the SHA-256 and invalidates the existing authorization bundle.

Purpose separation prevents a valid signature for another control artifact, such as a principal policy or workspace registry, from authorizing a tool catalog.

The invocation references both:

    catalog_trust_policy
    catalog_signature_bundle

These are treated as control files. Like the principal, catalog, invocation and change plan, they must resolve outside the worker-writable workspace.

The broker records in audit context:
- tool catalog SHA-256;
- trust-policy SHA-256;
- signature-bundle SHA-256;
- successful signature-verification state;
- accepted signer identities.

The generic control-signature primitive already defines distinct purposes for tool catalogs, principal policies, workspace registries and the architecture contract. Only tool-catalog enforcement is wired into the execution path today; the remaining control artifacts are the next extension target.

## Reference signing CLI

The reference CLI exposes low-level signing and verification helpers for test/provisioning workflows:

    oryvael control-sign-hash \
      --private-key root.key \
      --signer-id root/tool-catalog \
      --purpose tool_catalog \
      --sha256 <catalog-sha256>

and:

    oryvael control-verify-hash \
      --policy control-trust-policy.json \
      --bundle catalog-signatures.json \
      --purpose tool_catalog \
      --sha256 <catalog-sha256>

Production private root keys must not be present in the repository, AI workspace or ordinary execution host. The committed deterministic private seed under `examples/test-fixtures/` is explicitly test-only and provides no production secrecy or authority. A production implementation should use an offline or HSM-backed signing process and distribute public trust policy only.

## Change-plan binding

Before execution the broker hashes:
- principal policy;
- signed tool catalog;
- catalog trust policy;
- catalog signature bundle;
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

A brokered action executes through:

    protected invocation
        |
    catalog root-trust verification
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

Principal policies, workspace registries and the architecture contract are hash/audit bound but do not yet require the generic control-signature primitive in their runtime paths.

Git mutation remains in the dedicated Workspace Broker rather than being exposed as a generic writable Git tool action.

The current fuzz-smoke profile is deterministic and bounded; coverage-guided fuzzing is not yet implemented.
