# ORYVAEL native bare-metal quickstart

ORYVAEL boots as a native x86_64 UEFI operating-system image. The guest does not run Linux, Debian, Ubuntu, Alpine or another host operating system beneath it.

For complete host-specific commands for Windows, Linux and macOS — including QEMU user-mode NAT, administrator-key provisioning and SSH — see [`try-oryvael.md`](try-oryvael.md).

## What exists now

The development image currently provides:

- freestanding Rust `no_std` kernel;
- direct `EFI/BOOT/BOOTX64.EFI` UEFI entry;
- `ExitBootServices` firmware handoff;
- physical frame allocator and kernel heap;
- ORYVAEL-owned CR3/PML4 root with a ring-3 address-space branch;
- GDT/TSS, exception gates, PIT/PIC timer and DPL3 syscall boundary;
- first CPL3 `init` payload with measured timer preemption;
- capability-checked mailbox IPC and RAM filesystem;
- UEFI GOP framebuffer retention after firmware handoff;
- software-backbuffer 2D graphics primitives and a timer-driven boot animation;
- RTL8139 networking with DHCP, ARP, IPv4, ICMP and DNS;
- deliberately small in-order TCP path;
- SSHv2 with Ed25519 public-key authentication;
- serial/PS2 recovery console;
- QEMU/OVMF integration tests covering the native boot path.

## Build requirements

The Unix build script needs:

- Rust via `rustup` (the repository pins Rust `1.85.0`);
- `dosfstools` (`mkfs.vfat` or `mkfs.fat`);
- `mtools` (`mcopy`);
- standard `dd`;
- QEMU and OVMF/EDK2 only for VM boot/testing.

Ubuntu/Debian example:

```sh
sudo apt-get update
sudo apt-get install -y git curl build-essential dosfstools mtools ovmf qemu-system-x86 openssh-client
```

macOS/Homebrew example:

```sh
brew install git qemu dosfstools mtools
```

## Provision a local SSH administrator key

The recommended local test layout is:

```sh
mkdir -p .oryvael
ssh-keygen -q -t ed25519 -N '' -f .oryvael/oryvael_admin -C oryvael-admin
```

`./scripts/build-os.sh` automatically detects `.oryvael/oryvael_admin.pub` and embeds only that public key in the image. The private key remains on the host and `.oryvael/` is ignored by Git.

A different OpenSSH Ed25519 public key can be supplied explicitly:

```sh
ORYVAEL_ADMIN_PUBKEY_FILE=/path/to/admin.pub ./scripts/build-os.sh
```

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

Headless serial mode:

```sh
./scripts/run-os.sh
```

GUI mode, including the native GOP framebuffer animation:

```sh
./scripts/run-os.sh --gui
```

The launcher uses QEMU user-mode NAT and creates this host-local mapping:

```text
127.0.0.1:2222 -> guest tcp/22
```

Equivalent QEMU networking arguments:

```text
-device rtl8139,netdev=net0
-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22
```

No TAP adapter or host bridge is required for the recommended test path.

To use another host SSH port:

```sh
./scripts/run-os.sh --gui --ssh-port 2223
```

## SSH

After ORYVAEL reports that SSH is listening:

```sh
ssh -i .oryvael/oryvael_admin -p 2222 admin@127.0.0.1
```

The SSH shell currently exposes:

```text
help
whoami
ip
uptime
reboot
exit
```

Password, `system` and root remote login are disabled.

## Recovery console

The local recovery console exposes:

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
version
banner
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

`debug` prints a kernel diagnostic snapshot. `ip` reports the DHCP address, mask, gateway, DNS and MAC. `net` reports the RTL8139, DHCP and packet counters. `ping HOST` performs native DNS A lookup when needed and then ICMP echo.

## Expected boot evidence

A current QEMU/OVMF boot should include evidence similar to:

```text
[  OK  ] Firmware handoff complete
[  OK  ] Native graphics engine online
[ INFO ] Display width: 1280
[ INFO ] Display height: 800
[  OK  ] Framebuffer animation self-test complete
[  OK  ] Ring-3 transition verified
[  OK  ] DHCP lease acquired
[ INFO ] IPv4 address: 10.0.2.15
[  OK  ] Scheduler and recovery console ready
ORYVAEL SYSTEM READY
```

The `10.0.2.15` address is the current QEMU user-network observation, not an API contract. Host SSH should use the explicit localhost forward.

## Runtime boundary

```text
hardware / QEMU
    |
UEFI firmware handoff
    |
ExitBootServices
    |
ORYVAEL kernel (CPL0)
    |- physical allocator + kernel heap
    |- ORYVAEL CR3 / PML4 root
    |- GDT + TSS + exceptions + timer
    |- GOP framebuffer + software backbuffer
    |- syscall / capability boundary
    |- RAMFS
    |- RTL8139 + DHCP/ARP/IPv4/ICMP/DNS/TCP
    |- SSHv2 / Ed25519 -> admin identity
    `- ring-3 address space
              |
         ORYVAEL init (CPL3)
```

## Current limits

The graphics path is a kernel-level framebuffer bring-up, not yet a user-space display service or compositor. The filesystem remains RAM-only. The scheduler still runs one ring-3 process to completion rather than context-switching multiple runnable processes. The networking stack is intentionally small and the SSH server is single-session. The SSH host identity is still a development identity embedded in the image.

See [`PROJECT_STATUS.md`](../../PROJECT_STATUS.md) for the authoritative delivered/not-delivered snapshot.
