param(
    [string]$QemuPath = "C:\Program Files\qemu\qemu-system-x86_64.exe",
    [ValidateSet("User", "Tap")]
    [string]$NetworkMode = "User",
    [string]$TapAdapter = "OpenVPN TAP-Windows6"
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
    "-display", "gtk,show-tabs=on",
    "-vga", "none",
    "-serial", "vc",
    "-monitor", "none",
    "-device", "rtl8139,netdev=net0"
)

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
    # Keep the guest reachable from Windows without requiring a TAP adapter.
    # SSH listens on guest port 22; use localhost:2222 on the host.
    $qemuArgs += @("-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22")
}

# Keep QEMU attached to this launcher. Passing the argument array directly
# preserves adapter names and firmware paths exactly on Windows. There is no
# -no-reboot flag, so the ORYVAEL `reboot` command restarts the guest.
& $QemuPath @qemuArgs
