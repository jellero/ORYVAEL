# Try ORYVAEL in QEMU

This guide boots the current x86_64 UEFI development image, gives it outbound networking through QEMU's user-mode NAT and forwards host TCP port `2222` to ORYVAEL SSH on guest port `22`.

ORYVAEL is research-stage software. Use this flow on a development machine or disposable VM, not as a production deployment.

## Network model

The recommended test topology is deliberately host-local:

```text
host SSH client
127.0.0.1:2222
        |
        | hostfwd
        v
QEMU user-mode NAT (SLIRP)
        |
        | private guest network + DHCP
        v
ORYVAEL net0
TCP/22 SSH
```

QEMU creates the NAT when the VM starts. No persistent host NAT, TAP adapter, bridge, Internet Connection Sharing or root/admin network configuration is required.

The launchers use these QEMU network arguments:

```text
-device rtl8139,netdev=net0
-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22
```

Binding the forward to `127.0.0.1` means SSH is reachable from the host only; it is not exposed to the LAN.

The current QEMU/OVMF integration test normally gives the guest `10.0.2.15`, but clients should connect through `127.0.0.1:2222` rather than depend on that DHCP address.

## Administrator key provisioning

The SSH server accepts Ed25519 public-key authentication only. The build tooling automatically uses `.oryvael/oryvael_admin.pub` when that file exists and embeds only the 32-byte Ed25519 public key into the development image.

The matching private key stays on the host in `.oryvael/oryvael_admin` and `.oryvael/` is ignored by Git.

You can also point the build at another OpenSSH Ed25519 public key:

```sh
ORYVAEL_ADMIN_PUBKEY_FILE=/absolute/path/to/admin.pub ./scripts/build-os.sh
```

The current SSH host identity is still a development identity embedded in the image. Do not treat this image as production-secure or expose its SSH listener directly to an untrusted network.

## Windows 10/11

The recommended Windows path builds the image through WSL and runs QEMU natively on Windows.

### Requirements

- Git for Windows
- WSL2 with Ubuntu
- QEMU for Windows
- Windows OpenSSH client

Official references:

- WSL: <https://learn.microsoft.com/windows/wsl/install>
- OpenSSH on Windows: <https://learn.microsoft.com/windows-server/administration/openssh/openssh-install-first-use>
- QEMU downloads: <https://www.qemu.org/download/>
- Rust: <https://rustup.rs/>

Open an elevated PowerShell for the host prerequisites:

```powershell
winget install --id Git.Git -e
winget install --id SoftwareFreedomConservancy.QEMU -e
wsl --install
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

If WSL was installed for the first time, restart Windows before continuing.

Clone ORYVAEL in a normal PowerShell window:

```powershell
git clone https://github.com/jellero/ORYVAEL.git
Set-Location ORYVAEL
```

Install the Linux-side build tools and Rust inside WSL. `wsl` runs the command from the current Windows directory, so the generated `dist/` files remain directly accessible to Windows QEMU:

```powershell
wsl bash -c 'sudo apt-get update && sudo apt-get install -y curl build-essential dosfstools mtools && if ! command -v rustup >/dev/null 2>&1; then curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; fi'
```

Generate a local administrator key. This command uses Windows OpenSSH, so the private key receives normal Windows file permissions:

```powershell
New-Item -ItemType Directory -Force .oryvael | Out-Null
cmd.exe /d /s /c 'ssh-keygen -q -t ed25519 -N "" -f .oryvael\oryvael_admin -C oryvael-admin'
```

Build the UEFI image through WSL:

```powershell
wsl bash -c '. "$HOME/.cargo/env" && ./scripts/build-os.sh'
```

Expected outputs:

```text
dist/oryvael-x86_64-uefi.img
dist/BOOTX64.EFI
```

Start QEMU with GUI graphics and user-mode NAT:

```powershell
.\scripts\run-os.cmd -NetworkMode User -DisplayMode Gui
```

The launcher creates this mapping automatically:

```text
127.0.0.1:2222 -> ORYVAEL tcp/22
```

In a second PowerShell window, from the repository directory:

```powershell
ssh -i .\.oryvael\oryvael_admin -p 2222 admin@127.0.0.1
```

For a headless serial run:

```powershell
.\scripts\run-os.cmd -NetworkMode User -DisplayMode Headless
```

If port `2222` is already in use, choose another host port, for example `2223`:

```powershell
.\scripts\run-os.cmd -NetworkMode User -DisplayMode Gui -SshHostPort 2223
ssh -i .\.oryvael\oryvael_admin -p 2223 admin@127.0.0.1
```

## Linux (Ubuntu/Debian)

Install host requirements:

```sh
sudo apt-get update
sudo apt-get install -y git curl build-essential dosfstools mtools ovmf qemu-system-x86 openssh-client
```

Install Rust with rustup if it is not already installed:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

Clone the source and generate a local administrator key:

```sh
git clone https://github.com/jellero/ORYVAEL.git
cd ORYVAEL
mkdir -p .oryvael
ssh-keygen -q -t ed25519 -N '' -f .oryvael/oryvael_admin -C oryvael-admin
```

Build the image:

```sh
./scripts/build-os.sh
```

Launch QEMU with the GOP graphics window visible. The launcher creates user-mode NAT and forwards localhost port `2222` to guest SSH:

```sh
./scripts/run-os.sh --gui
```

In a second terminal:

```sh
ssh -i .oryvael/oryvael_admin -p 2222 admin@127.0.0.1
```

For a headless run:

```sh
./scripts/run-os.sh
```

To use another host port:

```sh
./scripts/run-os.sh --gui --ssh-port 2223
ssh -i .oryvael/oryvael_admin -p 2223 admin@127.0.0.1
```

## macOS

The supported development path uses Homebrew QEMU plus the same x86_64 UEFI image. On Apple Silicon, QEMU emulates the x86_64 CPU rather than virtualizing it, so it can be slower than an x86_64 host.

Install Homebrew first if needed: <https://brew.sh/>

Then install the host tools:

```sh
brew install git qemu dosfstools mtools
```

Install Rust with rustup if it is not already installed:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

Clone ORYVAEL and generate a local administrator key:

```sh
git clone https://github.com/jellero/ORYVAEL.git
cd ORYVAEL
mkdir -p .oryvael
ssh-keygen -q -t ed25519 -N '' -f .oryvael/oryvael_admin -C oryvael-admin
```

Build the UEFI image:

```sh
./scripts/build-os.sh
```

The build script accepts the Homebrew `dosfstools`/`mtools` utilities and does not require GNU `truncate`.

Launch QEMU. The launcher discovers the EDK2 firmware shipped by the Homebrew QEMU formula and creates the same localhost-only NAT forward:

```sh
./scripts/run-os.sh --gui
```

In a second terminal:

```sh
ssh -i .oryvael/oryvael_admin -p 2222 admin@127.0.0.1
```

To use another host port:

```sh
./scripts/run-os.sh --gui --ssh-port 2223
ssh -i .oryvael/oryvael_admin -p 2223 admin@127.0.0.1
```

## What to expect

A successful boot should report the native graphics bring-up, CPL3 transition, DHCP and SSH service before reaching the recovery console. Under the current QEMU/OVMF integration target, representative output includes:

```text
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

After SSH authentication:

```text
Welcome to ORYVAEL secure shell
Authenticated as admin (uid 1000)
oryvael::admin>
```

Useful remote commands:

```text
help
whoami
ip
uptime
reboot
exit
```

## NAT and SSH troubleshooting

Check whether the host forward is already occupied.

Windows PowerShell:

```powershell
Get-NetTCPConnection -LocalPort 2222 -ErrorAction SilentlyContinue
```

Linux:

```sh
ss -ltnp | grep ':2222'
```

macOS:

```sh
lsof -nP -iTCP:2222 -sTCP:LISTEN
```

If the port is occupied, use `-SshHostPort` on Windows or `--ssh-port` on Linux/macOS and connect SSH to the same alternate host port.

If SSH returns `Permission denied (publickey)`, rebuild the image after generating `.oryvael/oryvael_admin.pub`; the public key is embedded at build time and must match the private key passed to `ssh -i`.

If QEMU starts but no graphical window is wanted, use the documented headless mode. Headless mode still keeps the emulated VGA/GOP device present so the graphics self-test can run; it only suppresses the host display window.
