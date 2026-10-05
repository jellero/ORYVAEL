# ORYVAEL Workloads — Container philosophy, evolved

Status: architecture target with an executable manifest contract in the host-side reference tooling. The native workload runtime is **not yet implemented** in the bare-metal image.

## Thesis

Containers made software portable by packaging an application and isolating its execution environment.

ORYVAEL extends that idea by making **authority portable and explicit**.

> **Containers were an abstraction over processes. ORYVAEL Workloads are an abstraction over authority.**

An ORYVAEL workload is not defined only by an image. It is defined by:

- an immutable, content-addressed artifact;
- an explicit principal identity;
- a capability set;
- resource budgets;
- an object namespace;
- network policy;
- volumes and secret operations;
- lifecycle state;
- attributable audit evidence.

The goal is to retain the strongest parts of the container developer experience — reproducibility, image distribution, fast lifecycle, registry workflows and isolation — without inheriting ambient Unix root authority as the native security model.

## The conceptual evolution

~~~text
Traditional container

image
  + namespaces
  + cgroups
  + seccomp
  + UID/GID/root semantics
        |
     Linux kernel

ORYVAEL Workload

verified artifact
  + principal
  + capability table
  + resource budget
  + object namespace
  + volumes / secret operations
  + evidence
        |
     ORYVAEL kernel
~~~

The objective is not to claim that Linux containers are weak. Their isolation model is mature and useful. ORYVAEL starts from a different primitive: possession of an explicit object capability, rather than ambient authority later constrained by several independent mechanisms.

## Invariants

A native ORYVAEL workload must preserve these rules:

1. **deny by default** — absent authority is denial;
2. **no privileged mode** — there is no workload equivalent of unrestricted `--privileged`;
3. **no root escape hatch** — a UID or compatibility identity cannot widen native authority;
4. **no self-grant** — a workload cannot add capabilities to itself;
5. **immutable artifact identity** — executable content is bound to a digest;
6. **secrets are operations where possible** — signing/decryption handles are preferred to raw secret export;
7. **network authority is explicit** — the default network policy is deny;
8. **resource ownership is explicit** — CPU, memory and process budgets are part of the workload contract;
9. **lifecycle is attributable** — create/start/stop/restart/replace operations produce audit evidence;
10. **compatibility does not redefine trust** — POSIX/Linux compatibility remains a facade above the ORYVAEL authority model.

## Native object model

After Native Phase 2 provides process isolation, principal identity and kernel object handles, a workload can be represented as a system object composed from those primitives.

~~~text
Workload
  id
  artifact_digest
  principal_id
  isolation_mode
  process_set
  handle_table / authority template
  resource_budget
  object_namespace
  volume_attachments
  secret_handles
  network_endpoints
  lifecycle_state
  audit_identity
~~~

Starting a workload becomes an authority transaction rather than merely a process launch:

~~~text
artifact fetch / local artifact
           |
           v
content digest verification
           |
           v
manifest validation
           |
           v
policy evaluation
           |
           v
principal creation / binding
           |
           v
capability + resource instantiation
           |
           v
isolated process or microVM
           |
           v
runtime evidence + audit
~~~

## Workload manifest v1

The first machine-readable contract is `spec/workload-manifest.schema.json`.

A minimal example:

```json
{
  "version": "oryvael-workload/1",
  "id": "example.web",
  "artifact": {
    "format": "oci",
    "reference": "oci://registry.example/oryvael/web@sha256:...",
    "digest": "sha256:...",
    "platform": "oryvael/x86_64"
  },
  "isolation": "process",
  "entrypoint": ["/app/web", "--listen", "0.0.0.0:8080"],
  "resources": {
    "memory_bytes": 268435456,
    "cpu_millis_per_second": 250,
    "max_processes": 8
  },
  "network": {
    "default": "deny"
  },
  "capabilities": [
    {
      "resource": "socket:tcp/8080",
      "actions": ["listen", "accept"]
    },
    {
      "resource": "directory:/app",
      "actions": ["read", "enumerate"]
    }
  ]
}
```

The reference CLI can validate the executable contract now:

```sh
cargo run --locked -p oryvael-cli -- workload-check examples/workloads/web.json
```

An empty JSON array means the manifest passed the current semantic checks.

This command is host-side reference tooling. It does **not** mean the native kernel can launch the workload yet.

## OCI compatibility

ORYVAEL should reuse OCI where it creates leverage, especially for:

- registry APIs;
- content-addressed manifests and layers;
- digest-based distribution;
- signatures and attestations;
- caching;
- SBOM/provenance attachment;
- multi-platform artifacts.

OCI is treated as a **distribution envelope**, not as a requirement to reproduce `runc` or Linux namespaces inside ORYVAEL.

A future registry may contain targets such as:

~~~text
oryvael/x86_64
oryvael/aarch64
linux/x86_64
linux/aarch64
~~~

`oryvael/*` artifacts execute through the native workload runtime.

`linux/*` artifacts require an explicit compatibility path — for example a Linux ABI compatibility service or a confined Linux microVM. A Linux OCI artifact must never be presented as natively executable merely because ORYVAEL can download its layers.

## Isolation modes

The workload contract defines two target isolation modes.

### `process`

The normal, lightweight mode:

- native ORYVAEL address-space isolation;
- per-workload principal;
- capability handles;
- resource accounting;
- explicit volumes/network/secrets;
- shared ORYVAEL kernel.

This is the natural replacement for the common container use case.

### `microvm`

A stronger boundary for hostile or compatibility workloads:

- dedicated virtual machine boundary;
- explicit virtual devices;
- bounded CPU and memory;
- explicit storage/network attachments;
- the same workload lifecycle and audit model above the VM boundary.

The long-term UX should allow the isolation mode to change without redefining application authority.

## No native `root`

A workload may expose UID/GID semantics to software that expects them, but those values do not define native ORYVAEL authority.

For example, a web workload might receive:

~~~text
principal: workload:example.web

socket:tcp/8080
    LISTEN
    ACCEPT

directory:/app
    READ
    ENUMERATE

directory:/tmp
    READ
    WRITE

secret:tls-web
    SIGN
~~~

It does not receive:

~~~text
kernel.*
policy.*
capability.*
root.*
audit.delete
~~~

A process running as compatibility UID 0 still cannot operate on an object for which its ORYVAEL process has no capability handle.

## Volumes

Persistent state must remain separate from immutable application artifacts.

~~~text
immutable artifact
      +
read-only application root
      +
explicit writable scratch
      +
attached persistent volumes
~~~

A workload manifest identifies volume attachments by logical ID and target path. The runtime resolves that ID to a storage object through policy; the manifest does not grant arbitrary host filesystem traversal.

This gives updates a clean model:

~~~text
old artifact + volume
          |
new verified artifact
          |
attach same authorized volume
          |
health / evidence gate
          |
commit or rollback
~~~

## Secrets

The v1 contract intentionally exposes only bounded secret operations such as:

- `sign`;
- `decrypt`.

The design preference is:

~~~text
workload
   |
secret operation handle
   |
key / secret service
   |
result
~~~

rather than copying a raw private key into an application filesystem or environment variable.

## Target developer experience

The intended native CLI is deliberately familiar:

~~~text
oryvael pull registry.example/acme/web:1
oryvael inspect acme/web:1
oryvael run web --artifact acme/web:1
oryvael ps
oryvael logs web
oryvael stop web
oryvael rm web
~~~

Those lifecycle commands are **target API**, not delivered commands today.

What changes compared with a classic container workflow is that `run` is expected to make authority visible:

~~~text
Artifact
  acme/web@sha256:...

Requested authority
  socket:tcp/8080     LISTEN, ACCEPT
  directory:/app      READ, ENUMERATE
  directory:/tmp      READ, WRITE

Resources
  memory              256 MiB
  cpu                 250 ms/s
  processes           8

Network default
  DENY

Policy decision
  eligible
~~~

There should be no hidden transition equivalent to “run this with every privilege”.

## AI-native workload flow

The workload runtime is a natural execution substrate for ORYVAEL AI.

Example:

~~~text
Human: run this repository and test it
            |
            v
Developer AI analyzes source
            |
            v
proposes artifact + workload manifest
            |
            v
Security AI evaluates dependencies / behavior / authority
            |
            v
policy compares requested authority with allowed authority
            |
            v
human approval if required
            |
            v
isolated workload instance
            |
            v
tests + telemetry + evidence
            |
            v
destroy or promote artifact
~~~

The AI may propose a workload contract. It does not approve its own authority.

## Security AI and behavioral authority

Because authority is structured, runtime telemetry can answer semantically useful questions:

~~~text
principal    workload:example.web
artifact     sha256:...
object       socket:tcp/443
action       connect
decision     denied
reason       capability absent
~~~

A security analyzer can compare:

- declared authority;
- granted authority;
- authority actually used;
- denied attempts;
- artifact/SBOM changes;
- network and storage behavior.

This creates a richer signal than raw syscall names alone.

## Runtime architecture target

~~~text
Registry / local artifact store
             |
             v
      Artifact verifier
             |
             v
      Workload manager
       /      |       \
      /       |        \
 principal  policy   resources
      |       |        |
      +-------+--------+
              |
       object handles
              |
        process / microVM
              |
   +----------+----------+
   |          |          |
 storage    network    secrets
   |          |          |
   +----------+----------+
              |
          audit/evidence
~~~

## Dependency on Native Phase 2

The runtime should not be implemented as an ad-hoc container subsystem before its security primitives exist.

Required Native Phase 2 foundations:

1. multi-process scheduling;
2. per-process address spaces and recoverable faults;
3. kernel object/handle tables;
4. principal identity;
5. grant/revoke/attenuation semantics;
6. blocking IPC/system services;
7. resource accounting;
8. entropy and durable identity;
9. attributed audit.

Once these exist, a workload is primarily orchestration of existing ORYVAEL primitives rather than a second security model.

## Post-Phase-2 implementation order

1. **Artifact store** — content-addressed immutable objects.
2. **Workload manager** — create/start/stop/replace lifecycle.
3. **Resource budgets** — memory, CPU, process and object quotas.
4. **Filesystem views** — immutable roots, scratch layers and volume attachments.
5. **Socket objects** — explicit network endpoints through the generalized socket subsystem.
6. **Secret handles** — signing/decryption without raw-key distribution.
7. **OCI registry client** — pull/push manifests and layers.
8. **Signed artifact policy** — publisher identity, provenance and verification gates.
9. **MicroVM isolation backend** — compatibility/high-risk workloads.
10. **AI workload broker** — allow AI to propose and operate only within policy-authorized workload contracts.

## Exit criteria

The first native workload milestone is complete when ORYVAEL can demonstrate all of the following on its own runtime:

- fetch or load a digest-addressed native artifact;
- validate its workload manifest;
- create a workload principal;
- instantiate a resource budget;
- create an isolated address space;
- attach only declared handles;
- start the workload;
- deny an undeclared object/network operation;
- stop and destroy the workload without leaking authority;
- preserve explicitly attached persistent state;
- produce attributed audit evidence for the lifecycle;
- replace the artifact and roll back without silently widening capability scope.

Only after those properties exist should ORYVAEL claim a native container-equivalent runtime.

## Current implementation boundary

Delivered now in the host-side reference tree:

- `spec/workload-manifest.schema.json`;
- Rust workload manifest types;
- semantic validation in `oryvael-protocol`;
- `oryvael workload-check`;
- `examples/workloads/web.json`;
- validation rules for deny-by-default networking, digest identity, resource bounds, wildcard rejection and reserved-authority rejection.

Not delivered yet in the bare-metal image:

- artifact store;
- workload lifecycle manager;
- OCI registry client;
- native volume service;
- generalized socket service;
- native secret service;
- multi-workload scheduler;
- microVM backend;
- `oryvael pull/run/ps/logs/stop/rm` native commands.

This distinction is intentional: the contract is being defined before the native runtime so the runtime can be built against explicit authority semantics rather than inventing them incrementally.
