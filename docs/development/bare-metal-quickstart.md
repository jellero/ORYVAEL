# ORYVAEL native bare-metal base

This is a native ORYVAEL operating-system base. The guest does not run Linux, Debian, Ubuntu, Alpine or another host operating system.

The x86_64 image boots through UEFI only for the platform handoff. ORYVAEL captures the firmware memory map, calls `ExitBootServices`, switches to its own top-level page table, installs its own privilege/interrupt structures, runs a first process at CPL3 and remains in control of the machine.

## What exists now

The native base provides:

- a freestanding Rust `no_std` kernel;
- direct x86_64 UEFI entry through `EFI/BOOT/BOOTX64.EFI`;
- retained firmware memory-map data after `ExitBootServices`;
- a native physical 4 KiB frame allocator built from UEFI conventional memory;
- a kernel bump heap owned by ORYVAEL;
- an ORYVAEL-owned PML4 root loaded into CR3;
- a fresh user page-table branch with separate ring-3 code, data and stack mappings;
- an ORYVAEL GDT and TSS with a dedicated kernel privilege-transition stack;
- 32 architectural exception gates with fail-closed diagnostics;
- a DPL3 `int 0x80` syscall gate;
- 8259 PIC routing plus a 100 Hz PIT clock for the current bootstrap PC target;
- a first `init` payload that actually executes at CPL3;
- timer preemption/accounting while `init` is executing in user mode;
- capability-checked mailbox IPC;
- a minimal RAM filesystem containing `/hello`;
- a polled RTL8139 PCI driver with DMA receive/transmit rings;
- DHCP address acquisition plus ARP, IPv4 and ICMP echo;
- direct 16550/COM1 console I/O and polled PS/2 input;
- a recovery kernel console;
- a QEMU/OVMF integration test that boots and exercises all of these boundaries.

The recovery console commands are:

```text
help
status
debug
net
ip
ping
users
whoami
ssh status
mem
uptime
alloc
vm
ps
fs
ipc
clear
about
reboot
```

`debug` prints a line-by-line kernel diagnostic snapshot. `ip` prints the
DHCP-provided address, mask, gateway, DNS and MAC. `net` reports PCI, driver,
DHCP and packet-counter details. `ping` verifies ICMP against the default
gateway, while `ping www.google.it` performs a native DNS A lookup followed by
an ICMP echo to the resolved address. `vm` reports the
ORYVAEL CR3 and user address-space base. `ps` reports the completed ring-3 init
and how many timer interrupts preempted it. `fs` exposes the RAMFS test file,
and `ipc` reports the capability-mailbox state.

`users` exposes the native account registry and `whoami` reports the current
kernel-console identity. `ssh status` reports the native TCP/SSHv2 listener.
Password, `system` and root login are disabled; the remote `admin` account uses
only its explicitly provisioned Ed25519 key.

The Windows launcher maps host port 2222 to guest port 22. After boot:

```powershell
ssh -i $env:USERPROFILE\.ssh\oryvael_admin -p 2222 admin@127.0.0.1
```

The SSH shell provides `help`, `whoami`, `ip`, `uptime`, `reboot` and `exit`.

## Important current limits

The kernel owns the top-level PML4 and its fresh user branch, but lower-level kernel mappings inherited at UEFI handoff are still retained beneath the new root. They will be rebuilt natively in the next VM milestone.

The timer can interrupt a user process and the test proves that privilege transition, but the current scheduler boundary runs one `init` process to completion. It does not yet save/restore several runnable process contexts.

The current exception gates stop the system fail-closed with diagnostics. Per-process fault recovery/termination is not yet implemented.

The filesystem is RAM-only. There are no persistent storage drivers,
framebuffer desktop or native AI services yet. The bootstrap network stack is
limited to a polled RTL8139 target with DHCP, ARP, IPv4, ICMP echo and one
in-order TCP/SSHv2 session; it is not yet a general socket subsystem.

## Host build requirements

The build machine needs:

- Rust 1.85 via `rustup`;
- the Rust `x86_64-unknown-uefi` target;
- `dosfstools` and `mtools` to assemble the UEFI image;
- QEMU and OVMF only for VM boot/testing.

Those are host-side development tools. They are not present in the ORYVAEL image. On an Ubuntu/Debian development host, for example:

```sh
sudo apt-get install dosfstools mtools ovmf qemu-system-x86
```

This command affects only the development host. There is no Linux distribution in the ORYVAEL runtime image.

## Build

```sh
./scripts/build-os.sh
```

Outputs:

```text
dist/oryvael-x86_64-uefi.img
dist/BOOTX64.EFI
```

## Boot in QEMU

```sh
./scripts/run-os.sh
```

A successful native-userspace boot now presents a branded, operator-friendly sequence:

```text
============================================================
                      O R Y V A E L
============================================================
 Sovereign AI-Native Operating System  |  x86_64 UEFI
 Intelligence proposes. Humans authorize. ORYVAEL enforces.

Boot sequence
 [  OK  ] Firmware entry accepted
 [  OK  ] Firmware handoff complete
 [  OK  ] Native kernel online
 ...
 [  OK  ] Ring-3 transition verified
 [  25% ] Timer preemption verified
 [  50% ] Syscall gateway verified
 [  75% ] Isolation loop scheduled
 [ 100% ] Preemption proof complete
 [  OK  ] Scheduler and recovery console ready

ORYVAEL SYSTEM READY

+----------------------------------------------------------+
|                 Welcome to ORYVAEL                       |
+----------------------------------------------------------+
oryvael::system>
```

The default QEMU runner uses the serial terminal as the interactive recovery console.

## Runtime boundary

```text
hardware / QEMU
    ↓
UEFI firmware handoff
    ↓
ExitBootServices
    ↓
ORYVAEL kernel (CPL0)
    ├─ physical allocator + kernel heap
    ├─ ORYVAEL CR3 / PML4 root
    ├─ GDT + TSS + exceptions + timer
    ├─ syscall / capability boundary
    ├─ RAMFS
    ├─ RTL8139 + DHCP/ARP/IPv4/ICMP/DNS/TCP
    ├─ SSHv2 / Ed25519 → admin identity
    └─ ring-3 address space
              ↓
         ORYVAEL init (CPL3)
```

The runtime boundary is fully native: firmware hands control directly to the ORYVAEL kernel.

## Next native milestones

1. Replace all inherited lower-level kernel mappings with ORYVAEL-built page tables.
2. Turn user faults into process termination/recovery instead of a whole-kernel fail-closed halt.
3. Replace legacy PIT/PIC with local APIC/IOAPIC routing.
4. Save/restore contexts and schedule multiple runnable ring-3 processes.
5. Generalize the capability mailbox into kernel objects, rights and blocking IPC.
6. Add persistent storage and a filesystem service.
7. Add framebuffer/graphics, generalize the current TCP/SSH path and add NIC interrupts.
