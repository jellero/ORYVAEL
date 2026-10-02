# Local Supervisor Quickstart

The Phase 1 supervisor is Linux-only.

## Prerequisites

Ubuntu/Debian:

    sudo apt-get update
    sudo apt-get install bubblewrap util-linux

Fedora:

    sudo dnf install bubblewrap util-linux

Build ORYVAEL:

    cargo build --workspace

## Run the confinement demo

Remove prior demo state if desired:

    rm -rf /tmp/oryvael-demo-workspace /tmp/oryvael-demo-control

Run:

    cargo run -p oryvael-cli -- supervise \
      --principal examples/supervisor/developer-principal.json \
      --job examples/supervisor/job.json

Expected result:
- generated.txt exists under /tmp/oryvael-demo-workspace;
- writing /oryvael-escape from inside the worker fails;
- network connection from the worker fails;
- stdout and stderr are copied to the external content-addressed artifact store;
- the external JSONL audit chain contains request, policy, start and exit events.

Verify audit:

    cargo run -p oryvael-cli -- audit-verify \
      /tmp/oryvael-demo-control/audit.jsonl

## Control-file rule

Do not put the principal policy or job specification inside the job workspace.

The supervisor rejects this configuration because an untrusted worker must not be able to rewrite the control inputs used for its next invocation.

## Granting read-only host data

Add the path to read_only_paths in the job and grant:

    resource: host_path
    action: read
    scope: /exact/canonical/path

The path is mounted read-only. A missing capability denies the job before Bubblewrap starts.

## Granting network

Network mode is deny by default.

To share host networking, the job must set network to host and the principal must explicitly allow:

    resource: network
    action: connect
    scope: "*"

ORYVAEL does not silently enable networking because a worker requests it.

## Current boundary

The supervisor isolates the worker and all of its child processes inside the same filesystem/network boundary. Phase 1 does not yet broker every child exec individually.

The next phase will put compiler, test runner, Git and other privileged development tools behind brokered tool capabilities.
