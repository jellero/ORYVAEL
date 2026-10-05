param(
    [string]$QemuPath = "C:\Program Files\qemu\qemu-system-x86_64.exe",
    [ValidateSet("User", "Tap")]
    [string]$NetworkMode = "User",
    [string]$TapAdapter = "OpenVPN TAP-Windows6",
    [ValidateSet("Gui", "Headless")]
    [string]$DisplayMode = "Gui",
    [ValidateRange(1, 65535)]
    [int]$SshHostPort = 2222
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$distDir = Join-Path $repoRoot "dist"
$image = Join-Path $distDir "oryvael-x86_64-uefi.img"
$firmwareDir = Join-Path (Split-Path -Parent $QemuPath) "share"
$codeSource = Join-Path $firmwareDir "edk2-x86_64-code.fd"
$varsSource = Join-Path $firmwareDir "edk2-i386-vars.fd"
$code = Join-Path $distDir "qemu-code.fd"
$vars = Join-Path $distDir "qemu-vars.fd"

foreach ($required in @($QemuPath, $image, $codeSource, $varsSource)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required file not found: $required"
    }
}

# Local firmware paths avoid Windows argument parsing issues with Program Files.
Copy-Item -LiteralPath $codeSource -Destination $code -Force
Copy-Item -LiteralPath $varsSource -Destination $vars -Force

$qemuArgs = @(
    "-machine", "q35",
    "-cpu", "qemu64",
    "-m", "256M",
    "-drive", "if=pflash,format=raw,readonly=on,file=$code",
    "-drive", "if=pflash,format=raw,file=$vars",
    "-drive", "if=virtio,format=raw,file=$image",
    "-vga", "std",
    "-monitor", "none",
    "-device", "rtl8139,netdev=net0"
)

if ($DisplayMode -eq "Headless") {
    $qemuArgs += @("-display", "none", "-serial", "stdio")
} else {
    $qemuArgs += @("-display", "gtk,show-tabs=on", "-serial", "vc")
}

if ($NetworkMode -eq "Tap") {
    $adapter = Get-NetAdapter -Name $TapAdapter -ErrorAction SilentlyContinue
    if ($null -eq $adapter) {
        throw "TAP adapter '$TapAdapter' not found. Install TAP-Windows6 and create this adapter first."
    }
    if ($adapter.InterfaceDescription -notmatch "TAP-Windows") {
        throw "'$TapAdapter' is '$($adapter.InterfaceDescription)', not a TAP-Windows adapter. Use 'OpenVPN TAP-Windows6'."
    }
    $qemuArgs += @("-netdev", "tap,id=net0,ifname=$TapAdapter,script=no,downscript=no")
} else {
    # QEMU user networking creates a private NAT automatically. Binding the
    # forward to loopback keeps guest SSH reachable only from this host.
    $qemuArgs += @("-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:$SshHostPort-:22")
    Write-Host "ORYVAEL QEMU NAT: 127.0.0.1:$SshHostPort -> guest tcp/22"
}

# Keep QEMU attached to this launcher. Passing the argument array directly
# preserves firmware paths and adapter names exactly on Windows. There is no
# -no-reboot flag, so the ORYVAEL `reboot` command restarts the guest.
& $QemuPath @qemuArgs
