# Local Supervisor Quickstart

The Phase 1 supervisor is Linux-only.

## Prerequisites

Ubuntu/Debian:

    sudo apt-get update
    sudo apt-get install bubblewrap util-linux

Fedora:

    sudo dnf install bubblewrap util-linux

Build:

    cargo build --workspace

## Check the host

Run:

    ./target/debug/oryvael supervisor-doctor

The command reports Bubblewrap, unshare, prlimit and a real namespace probe.

If ready_for_basic_sandbox is true, the host supports the rootless reference path.

Some hardened distributions intentionally block unprivileged user namespaces. Do not disable AppArmor or weaken system policy merely to make the rootless probe pass. In the intended ORYVAEL OS model, a small trusted supervisor service creates the namespaces.

For the current standalone prototype that service path can be exercised with:

    sudo ./target/debug/oryvael supervisor-doctor

## Run the confinement demo

Clean prior demo state:

    rm -rf /tmp/oryvael-demo-workspace /tmp/oryvael-demo-control

If the rootless doctor passed:

    ./target/debug/oryvael supervise \
      --principal examples/supervisor/developer-principal.json \
      --job examples/supervisor/job.json

On a host where the rootless probe is blocked, exercise the trusted-service path:

    sudo ./target/debug/oryvael supervise \
      --principal examples/supervisor/developer-principal.json \
      --job examples/supervisor/job.json

Expected result:
- generated.txt exists under /tmp/oryvael-demo-workspace;
- the sandbox root is read-only outside /workspace;
- the test network connection is blocked;
- stdout/stderr are copied to the external SHA-256 artifact store;
- the external JSONL audit contains request, policy, start and exit events.

Verify audit:

    ./target/debug/oryvael audit-verify \
      /tmp/oryvael-demo-control/audit.jsonl

## Control-file rule

Never put the principal policy or job specification in the worker workspace.

The supervisor rejects this arrangement before execution because the worker must not be able to rewrite the authority inputs used for a future run.

## Read-only host data

Add a canonical host path to read_only_paths and grant:

    resource: host_path
    action: read
    scope: /exact/canonical/path

Without the grant, the job is denied before sandbox launch.

## Host networking

Network mode is deny by default.

To request host networking, the job must set network to host and the principal must independently contain an allow grant:

    resource: network
    action: connect
    scope: "*"

Changing only the job file does not create authority. The CI suite explicitly tests this negative case.

## Current boundary

The supervisor isolates the worker and its descendants inside one filesystem/network boundary.

Phase 2 will add brokered compiler, test-runner, Git and other tool operations so child execution itself becomes capability-addressable and independently auditable.
