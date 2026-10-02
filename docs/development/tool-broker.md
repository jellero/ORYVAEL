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

## Example

A catalog can expose:

    tool: python
    action: syntax-check
    executable: /usr/bin/python3
    argv: [-m, py_compile, /workspace/src/demo.py]
    network: deny

The developer principal must independently hold:

    resource: process
    action: execute
    scope: /usr/bin/python3

and:

    resource: tool
    action: execute
    scope: python.syntax-check

The change plan must also contain:

    requested_capabilities:
      - tool:python.syntax-check

Three independent conditions therefore have to agree:

1. catalog maps the name to a concrete operation;
2. change plan authorizes that operation for this change;
3. principal policy grants the runtime capability.

The supervisor performs the final capability check.

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

The initial broker intentionally has no user-provided trailing argument list.

Every action has fixed argv in the catalog.

This is restrictive by design. Structured parameters can be added later, but each parameter type must have explicit normalization and validation instead of being concatenated into a shell command.

No shell is used by the broker.

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

Network and additional host paths remain controlled by the catalog action and then independently authorized by the supervisor policy.

## Current limitations

The catalog itself is hashed but not yet signed by a constitutional key.

The next hardening step is a signed catalog/provenance model so a compromised ordinary system service cannot redefine a privileged action without producing an invalid authorization artifact.

Rust/Cargo tools also need explicit toolchain mounts because the supervisor deliberately does not expose the user's home directory.

Git write operations will be separated from read-only Git inspection so branch/worktree mutation can receive a distinct capability.
