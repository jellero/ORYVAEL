# Kernel Strategy

## Current decision

ORYVAEL is a bare-metal operating system with its own kernel and userland.
ADR-0005 supersedes the former Linux-first product-runtime decision in
ADR-0001.

Linux, Windows and macOS may host compilers, CI, image builders and QEMU, but
no host kernel is part of the ORYVAEL runtime boundary.

## Current native substrate

The first hardware contract is x86_64 UEFI. Firmware supplies the initial
memory map and image handoff. ORYVAEL then calls `ExitBootServices` and owns the
machine.

The implemented kernel currently provides:

- physical memory allocation and a kernel heap;
- an ORYVAEL-owned PML4/CR3 root plus isolated CPL3 mappings;
- GDT/TSS privilege transitions and architectural exception gates;
- PIT/PIC timer interrupts and a DPL3 syscall gateway;
- a first preempted ring-3 process;
- capability-checked IPC and RAMFS access;
- native RTL8139, DHCP, ARP, IPv4, ICMP, DNS and limited TCP;
- an Ed25519-authenticated SSHv2 administration boundary.

This is a bootstrap PC target rather than a general driver ecosystem. See
`PROJECT_STATUS.md` for the verified feature and limitation snapshot.

## Host reference code

The Linux-hosted Trusted Core remains valuable executable reference material
for policy, audit, approvals, release evidence and supervised AI tooling. Its
semantics are migration inputs for future native services; namespaces,
cgroups, seccomp, Landlock and Linux credentials are not ORYVAEL kernel
mechanisms.

## Kernel design direction

The native kernel will remain deterministic and deliberately separate
intelligence from authority:

- AI/model processes execute as untrusted ring-3 principals;
- resource access requires explicit kernel capabilities;
- privileged decisions are mediated by deterministic policy services;
- human/root authority remains outside model control;
- audit and approval state must become native durable services;
- unsafe Rust remains limited to documented firmware, CPU and device
  boundaries.

## Near-term engineering priorities

1. Own all lower-level kernel page tables rather than inheriting firmware
   mappings.
2. Implement saved contexts, kernel threads and multi-process scheduling.
3. Terminate faulty user processes without stopping the whole kernel.
4. Introduce APIC/IOAPIC and interrupt-driven device service.
5. Generalize capability objects, IPC, storage and networking.
6. Move identity, policy, audit and approval semantics into native services.
7. Add framebuffer/input support and later broader hardware drivers.
8. Add ARM64 only after the native kernel contracts stabilize.

Hardware breadth is not treated as evidence of authority correctness. Each new
driver and subsystem must preserve capability mediation and fail-closed
behavior.
