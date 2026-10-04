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

Build the x86_64 image:

```sh
./scripts/build-os.sh
```

Boot it in QEMU/OVMF:

```sh
./scripts/run-os.sh
```

The default console is the serial terminal. After boot, type `help` at the `oryvael>` prompt.

See `docs/development/bare-metal-quickstart.md` for host prerequisites, kernel services and the exact runtime boundary.

## Current status

ORYVAEL now has a minimally interactive bare-metal kernel base. It boots through UEFI, captures and retains the machine memory map, calls `ExitBootServices`, builds a physical 4 KiB frame allocator from conventional memory, initializes a kernel bump heap, installs an ORYVAEL IDT timer vector, remaps the legacy PIC, programs a 100 Hz PIT clock and starts a native serial/PS2 kernel console.

The live console currently exposes `help`, `mem`, `uptime`, `alloc`, `clear`, `about` and `reboot`. CI boots the real image in QEMU/OVMF and exercises allocator, timer and console commands rather than accepting boot text alone.

The existing trusted-core CI continues to validate governance and security semantics, but Linux sandbox mechanisms are reference/prototype infrastructure rather than the ORYVAEL OS substrate.

ORYVAEL is not yet a general-purpose or production-secure operating system. The next kernel boundary is ORYVAEL-owned page tables, complete exception handling, APIC routing, scheduling, ring-3 processes, capability IPC, drivers, storage and native userland services.

## Immediate kernel milestones

1. Own x86_64 page tables and virtual address-space management.
2. Install complete architectural exception handlers with fault diagnostics.
3. Replace the bootstrap PIT/PIC timer path with local APIC/IOAPIC routing.
4. Add kernel tasks and preemptive scheduling.
5. Enter ring 3 and launch the first ORYVAEL user process.
6. Implement capability-native IPC and object handles.
7. Add storage/filesystem, framebuffer/graphics and networking drivers/services.
8. Port governance, audit and root-control semantics from the host reference into native services.
9. Add an ARM64 boot path after the x86_64 kernel contracts stabilize.

## License

No license file is currently committed. A project license should be selected deliberately before accepting external code contributions.
