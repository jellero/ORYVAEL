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

### ORYVAEL Embedded / Edge

For IoT, robotics, gateways and physical-world controllers:
- deterministic device-side capability enforcement;
- authenticated device identity;
- signed updates, recovery and rollback where hardware permits;
- auditable hardware brokers for GPIO, buses, sensors and actuators;
- constrained Rust `no_std` runtimes for MCU-class targets;
- richer isolated workloads and optional WASM on Edge-class systems;
- no requirement for an on-device AI model;
- remote AI requests remain untrusted until local policy authorizes them.

The first experimental embedded direction is a RISC-V MCU/SoC backend, with ESP32-P4-class hardware as a candidate target. This is a separate architecture port rather than a direct build of the current x86_64 kernel.

The user experience and hardware mechanisms differ across profiles. The trust model does not.

See `docs/architecture/embedded-edge.md` for the Embedded / Edge authority boundary, portability model and prototype milestones.

## Repository map

- PROJECT_STATUS.md — verified native-runtime snapshot, limitations and next milestones
- kernel/ — freestanding ORYVAEL bare-metal kernel and native userspace bootstrap
- docs/vision.md — product vision
- docs/principles.md — engineering principles
- docs/architecture/ — system design, including the Embedded / Edge profile
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

After firmware handoff, ORYVAEL switches CR3 to an ORYVAEL-owned PML4 root. The existing kernel mappings are currently inherited beneath that new root during migration, while a fresh page-table branch is created for ring-3 user code, data and stack without widening the inherited supervisor mappings to user access.

The native x86_64 kernel installs its own GDT, TSS kernel stack, 32 architectural exception gates, timer interrupt path and DPL3 syscall gate. A first `init` payload runs at CPL3, is preempted by the kernel timer, crosses the syscall boundary, performs a capability-checked IPC mailbox roundtrip, reads `/hello` from an in-memory filesystem and exits back to the kernel.

The existing Linux trusted-core crates remain useful as a reference implementation for governance, policy, proof and audit semantics while those mechanisms migrate into native ORYVAEL kernel/system services. ADR-0005 supersedes the earlier Linux-first product direction.

Embedded/Edge targets reuse ORYVAEL authority semantics but require target-specific boot, isolation, interrupt, memory-protection and peripheral backends. Hardware that cannot enforce a required authority boundary must declare that limitation rather than silently weakening the contract.

Trusted components are written in Rust. Unsafe code remains forbidden by default and is allowed only at narrowly reviewed hardware/firmware/privilege boundaries under ADR-0005.

## Bare-metal quickstart

Build the x86_64 image:

```sh
./scripts/build-os.sh
```

Boot it in QEMU/OVMF:

```sh
./scripts/run-os.sh
```

On Windows, launch the existing image directly in QEMU user-network mode:

```powershell
.\scripts\run-os.cmd -NetworkMode User
```

The launcher forwards Windows port 2222 to ORYVAEL port 22. After boot:

```powershell
ssh -i "$env:USERPROFILE\.ssh\oryvael_admin" -p 2222 admin@127.0.0.1
```

The default console is the serial terminal. After the ring-3 init self-test completes, type `help` at the `oryvael::system>` recovery prompt.

See `docs/development/bare-metal-quickstart.md` for host prerequisites, kernel services and the exact runtime boundary.
See `PROJECT_STATUS.md` for the authoritative delivered/not-delivered snapshot.

## Current status

ORYVAEL now boots a native bare-metal x86_64 OS base with a real CPL3 boundary. The boot path provides a physical 4 KiB frame allocator, kernel heap, ORYVAEL-owned CR3/PML4 root, fresh user mappings, GDT/TSS, fail-closed architectural exception handling, a 100 Hz interrupt clock, DPL3 syscall gate, first ring-3 `init`, capability-checked IPC, a minimal RAM filesystem and a native RTL8139/DHCP/ARP/IPv4/ICMP/DNS/TCP network path.

The live integration test requires `init` to execute in ring 3 while timer interrupts occur, then verifies syscall output, the capability IPC value `42`, the RAMFS `/hello` read, a clean user exit and the recovery kernel console. The current test observed hundreds of timer preemptions while the user process was running.

The recovery console exposes `help`, `status`, `debug`, `ip`, `net`, `ping [host]`, `users`, `whoami`, `ssh status`, `mem`, `uptime`, `alloc`, `vm`, `ps`, `fs`, `ipc`, `clear`, `about`, `version`, `banner` and `reboot`. Hostname ping performs a native DNS A lookup before sending ICMP. The native account registry separates the kernel-console `system` identity from the remote `admin` identity. A native single-session TCP/IPv4 SSHv2 service listens on port 22 and permits only the provisioned Ed25519 key; password, `system` and root login are disabled.

The existing trusted-core CI continues to validate governance and security semantics, but Linux sandbox mechanisms are reference/prototype infrastructure rather than the ORYVAEL OS substrate. No model or inference runtime executes inside the native image yet; “AI-native” describes the target authority and capability architecture, not a completed embedded model runtime.

The Embedded / Edge profile is currently architectural only; no ESP32 or other MCU target is delivered yet.

This is a native minimal OS foundation, not yet a general-purpose or production-secure operating system. The current timer still uses PIT/PIC; only one ring-3 process is executed and preemption is measured rather than context-switched among multiple runnable processes; the kernel retains inherited lower-level mappings below its new PML4 root; the filesystem is RAM-only; persistent storage and graphics are not implemented yet. Networking currently targets a polled RTL8139 device and provides DHCP, ARP, IPv4, ICMP echo and a deliberately small single-session TCP/SSHv2 server rather than a general-purpose socket layer.

## Immediate kernel milestones

1. Rebuild the complete kernel virtual address space with ORYVAEL-owned lower-level page tables instead of retaining inherited firmware mappings.
2. Add recoverable per-process exception/fault termination on top of the current fail-closed architectural exception gates.
3. Replace PIT/PIC bootstrap routing with local APIC and IOAPIC.
4. Add kernel threads plus saved contexts and context-switch between multiple runnable ring-3 processes.
5. Grow the current capability mailbox into a kernel object/handle table with rights transfer and blocking IPC.
6. Add storage drivers and a persistent filesystem service beyond the current RAMFS.
7. Add framebuffer/graphics input, generalize the current TCP/SSH implementation and move the NIC to interrupt-driven service.
8. Port governance, audit and root-control semantics from the host reference into native services.
9. Add an ARM64 boot path after the x86_64 kernel contracts stabilize.
10. Define the architecture-neutral kernel contracts needed by the Embedded / Edge backend before introducing MCU-specific code into the runtime tree.

## License

No license file is currently committed. A project license should be selected deliberately before accepting external code contributions.
