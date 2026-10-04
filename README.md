# ORYVAEL

ORYVAEL is a research and engineering project for an AI-native operating system in which artificial intelligence can design, implement, test, integrate and maintain software while authority remains explicitly under human control.

The project does not assume that an AI becomes trustworthy enough to receive unrestricted administrator access. The architecture assumes the opposite: AI components are powerful but untrusted principals. Their actions must be scoped, observable, attributable, reproducible and reversible.

## Core thesis

**ORYVAEL separates intelligence from authority.**

An AI may analyze requirements, propose architecture, write code, create tests, run builds, perform security analysis, prepare release candidates, diagnose failures and propose repairs.

An AI may not implicitly grant capabilities to itself, change constitutional policy, modify the root of trust, disable audit, bypass mandatory verification, sign privileged releases or expand its own production scope.

## System planes

~~~
Human Governance
      |
Constitution / Root of Trust
      |
AI Control Plane
      |
Verification + Policy Plane
      |
System Services / Application Runtime
      |
ORYVAEL Kernel / Hardware
~~~

Observability and cryptographic audit cross every plane.

## Product profiles

### ORYVAEL Desktop

For workstations and general-purpose PCs:
- full windowed desktop;
- isolated developer workspaces;
- local AI agents;
- container/WASM workloads;
- explicit professional/admin capabilities;
- x86-64 and ARM64 targets.

### ORYVAEL Mobile

For phones and mobile devices:
- ARM64 first;
- touch-first shell;
- aggressive energy/resource budgets;
- secure-element identity;
- telephony, camera and sensor capabilities;
- the same app, capability and audit contracts as Desktop.

The user experience differs. The trust model does not.

## Repository map

- kernel/ — freestanding ORYVAEL bare-metal kernel
- docs/vision.md — product vision
- docs/principles.md — engineering principles
- docs/architecture/ — system design
- docs/security/ — threat model and invariants
- docs/governance/ — human authority
- docs/development/ — AI-native SDLC and bare-metal quickstart
- docs/roadmap.md — staged implementation
- adr/ — architecture decision records
- spec/ — machine-readable contracts
- crates/ — host-side trusted-core reference and migration source
- examples/ — example policies and manifests

## Trust zones

| Zone | Examples | Default |
|---|---|---|
| Root of Trust | constitutional policy, signing roots, recovery | human-controlled |
| Trusted Core | policy, audit, capability broker, artifact verifier | minimal deterministic code |
| Managed Intelligence | developer/test/security/release AI | untrusted, scoped |
| Untrusted Workload | apps, plugins, documents, web content | sandboxed |

No AI model belongs to the Root of Trust.

## Privileged change flow

~~~
human intent / issue
        |
     change plan
        |
architecture validation
        |
 capability grant
        |
 AI implementation
        |
independent verification
        |
   proof package
        |
 deterministic policy
        |
 release candidate
        |
 staged rollout
        |
 telemetry + audit
~~~

The implementation agent cannot approve its own change.

## Runtime strategy

ORYVAEL is a new operating system, not a Linux distribution and not a container layer. The product runtime owns its kernel and userland. Linux, macOS or Windows may be used as development hosts, but no host kernel is part of the ORYVAEL runtime boundary.

The first boot target is x86_64 UEFI. Firmware is used only for the initial machine handoff; the ORYVAEL kernel captures the memory map and terminates UEFI boot services before continuing bare-metal execution.

The existing Linux trusted-core crates remain useful as a reference implementation for governance, policy, proof and audit semantics while those mechanisms migrate into native ORYVAEL kernel/system services. ADR-0005 supersedes the earlier Linux-first product direction.

Trusted components are written in Rust. Unsafe code remains forbidden by default and is allowed only at narrowly reviewed hardware/firmware boundaries under ADR-0005.

## Bare-metal quickstart

Build the Stage 0 x86_64 image:

```sh
./scripts/build-os.sh
```

Boot it in QEMU/OVMF:

```sh
./scripts/run-os.sh
```

See `docs/development/bare-metal-quickstart.md` for host prerequisites and the exact runtime boundary.

## Current status

The repository now has a Stage 0 bare-metal kernel path in addition to the earlier host-side trusted-core prototype. Stage 0 is deliberately small: it boots through UEFI, captures the machine memory map, calls `ExitBootServices`, emits diagnostics directly through x86 port I/O and stays alive in an ORYVAEL-owned kernel idle loop.

The existing trusted-core CI continues to validate governance and security semantics, but Linux sandbox mechanisms are reference/prototype infrastructure rather than the ORYVAEL OS substrate.

ORYVAEL is not yet a general-purpose or production-secure operating system. Memory management, exceptions/interrupts, scheduling, processes, IPC, drivers and userland remain to be implemented natively.

## Immediate kernel milestones

1. Build the physical page allocator from the retained firmware memory map.
2. Install ORYVAEL GDT/IDT and exception handlers.
3. Bring up APIC timer and interrupt routing.
4. Own x86_64 page tables and virtual address-space management.
5. Add kernel tasks, preemptive scheduling and user-mode processes.
6. Implement capability-native IPC and object handles.
7. Start the first ORYVAEL userland service instead of the Stage 0 idle loop.
8. Port governance, audit and root-control semantics from the host reference into native services.
9. Add an ARM64 boot path after the x86_64 kernel contracts stabilize.

## License

No license file is currently committed. A project license should be selected deliberately before accepting external code contributions.
