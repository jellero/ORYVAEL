# Project Status

Snapshot: 2026-10-04  
Native kernel version: `0.0.2-dev`

ORYVAEL is a bootable bare-metal x86_64 operating-system foundation written in
Rust. It is not Linux, a Unix userland, a distribution, or a container layer.
It is not yet a production operating system or a complete native AI runtime.

## Native runtime delivered

- x86_64 UEFI image with direct `BOOTX64.EFI` entry;
- successful `ExitBootServices` handoff with no host OS beneath the guest;
- freestanding Rust `no_std` kernel;
- retained UEFI memory map, physical frame allocator and 256 KiB kernel heap;
- ORYVAEL-owned CR3/PML4 root with fresh ring-3 code, data and stack mappings;
- native GDT/TSS, exception gates, PIT/PIC timer and DPL3 syscall boundary;
- first CPL3 `init` payload with measured timer preemption;
- capability-checked IPC mailbox and RAM filesystem;
- RTL8139 driver with DHCP, ARP, IPv4, ICMP echo and DNS A lookup;
- outbound hostname ping and inbound ICMP echo replies;
- native single-session, in-order TCP listener;
- SSHv2 server using Ed25519 public-key authentication;
- separate `system` console and `admin` remote identities;
- password, root and remote `system` login disabled;
- serial/PS2 recovery console with aligned boot diagnostics;
- QEMU user-network forwarding from Windows `127.0.0.1:2222` to guest port 22;
- generated 64 MiB FAT/UEFI disk image containing a kernel payload of roughly
  236 KiB in the current build.

## Verified live behavior

- ORYVAEL receives DHCP address `10.0.2.15` under QEMU user networking;
- `ping www.google.it` performs native DNS resolution and receives ICMP replies;
- Windows OpenSSH authenticates `admin` using the provisioned
  `~/.ssh/oryvael_admin` Ed25519 key;
- remote `whoami` and `ip` commands execute successfully;
- the interactive SSH shell opens and exits cleanly;
- an unrelated Ed25519 key is rejected with `Permission denied (publickey)`;
- `reboot` restarts the virtual machine when QEMU is launched without
  `-no-reboot`.

## Host-side reference implementation

The root Cargo workspace still contains Linux-hosted reference components for
policy, audit, approvals, evidence, release gates, workspace isolation and
tool brokering. They provide executable semantics and migration source, but
they are not part of the bare-metal ORYVAEL runtime image.

## AI status

ORYVAEL is designed for native AI principals governed by explicit capabilities
and human authority. The bare-metal image does **not** yet contain a model,
inference runtime, tensor engine, GPU/NPU driver or native AI supervisor.

Today an external AI or human can interact with the development image through
the authenticated SSH/console boundary. Native AI execution begins only after
a ring-3 model/runtime service and the policy/capability control plane are
ported into the OS image.

## Important current limits

- one bootstrap CPU and one completed ring-3 process; no general context
  switching between multiple runnable processes;
- inherited lower-level firmware mappings remain below the ORYVAEL-owned PML4;
- PIT/PIC rather than APIC/IOAPIC;
- exceptions stop the kernel fail-closed rather than terminating one process;
- RAM-only filesystem and no persistent storage driver;
- polled RTL8139 networking rather than interrupt-driven multi-device sockets;
- one deliberately small in-order TCP/SSH session, not a general TCP stack;
- embedded development host identity and one provisioned administrator key;
- no framebuffer desktop, compositor, audio, USB, Wi-Fi or power management;
- no native AI model execution yet;
- no formal verification or production hardening claim.

## Next native milestones

1. Rebuild every kernel mapping with ORYVAEL-owned lower-level page tables.
2. Add saved process contexts, kernel threads and multi-process scheduling.
3. Add recoverable per-process faults and a native process lifecycle.
4. Replace PIT/PIC with local APIC and IOAPIC routing.
5. Replace the mailbox with capability object/handle tables and blocking IPC.
6. Add persistent block storage and a filesystem service.
7. Generalize TCP sockets, add retransmission/congestion handling and move the
   NIC to interrupt-driven operation.
8. Provision host/user keys outside the source image and add durable identity.
9. Add framebuffer/input services and the first native shell/desktop surface.
10. Port policy, audit and approval mechanisms into native system services.
11. Run the first governed AI worker at ring 3.

“Must” in architecture documents denotes a target requirement unless this
status file or executable evidence identifies it as delivered.
