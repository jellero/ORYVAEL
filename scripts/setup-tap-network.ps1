param(
    [string]$PublicAdapter = "Wi-Fi",
    [string]$TapAdapter = "OpenVPN TAP-Windows6"
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This setup must run as Administrator."
}

$public = Get-NetAdapter -Name $PublicAdapter -ErrorAction Stop
$tap = Get-NetAdapter -Name $TapAdapter -ErrorAction Stop
if ($tap.InterfaceDescription -notmatch "TAP-Windows") {
    throw "'$TapAdapter' is not a TAP-Windows adapter: $($tap.InterfaceDescription)"
}

Enable-NetAdapter -Name $TapAdapter -Confirm:$false

# Windows ICS uses 192.168.137.1/24 for its private interface. A stale binding
# on a disconnected adapter prevents ICS DHCP from attaching to the TAP and
# leaves both host and guest with 169.254/16 link-local addresses.
$conflicts = Get-NetIPAddress -IPAddress "192.168.137.1" -AddressFamily IPv4 `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -ne $tap.ifIndex }
foreach ($conflict in $conflicts) {
    $conflictAdapter = Get-NetAdapter -InterfaceIndex $conflict.InterfaceIndex `
        -ErrorAction SilentlyContinue
    if ($null -ne $conflictAdapter -and $conflictAdapter.Status -eq "Up") {
        throw "192.168.137.1 is active on '$($conflictAdapter.Name)'; refusing to remove it."
    }
    Write-Host "Removing stale 192.168.137.1 from '$($conflict.InterfaceAlias)'"
    Remove-NetIPAddress -InterfaceIndex $conflict.InterfaceIndex `
        -IPAddress "192.168.137.1" -Confirm:$false
}

$sharing = New-Object -ComObject HNetCfg.HNetShare
$publicConnection = $null
$tapConnection = $null
foreach ($connection in $sharing.EnumEveryConnection()) {
    $properties = $sharing.NetConnectionProps.Invoke($connection)
    if ($properties.Name -eq $PublicAdapter) {
        $publicConnection = $connection
    }
    if ($properties.Name -eq $TapAdapter) {
        $tapConnection = $connection
    }
}

if ($null -eq $publicConnection -or $null -eq $tapConnection) {
    throw "Unable to locate both adapters in Windows Internet Connection Sharing."
}

$publicConfig = $sharing.INetSharingConfigurationForINetConnection.Invoke($publicConnection)
$tapConfig = $sharing.INetSharingConfigurationForINetConnection.Invoke($tapConnection)
if ($publicConfig.SharingEnabled) {
    $publicConfig.DisableSharing()
}
if ($tapConfig.SharingEnabled) {
    $tapConfig.DisableSharing()
}

# 0 = public Internet connection, 1 = private home-network connection.
try {
    $publicConfig.EnableSharing(0)
    $tapConfig.EnableSharing(1)
} catch [System.Runtime.InteropServices.COMException] {
    if ($_.Exception.HResult -eq -2147220991) {
        Write-Warning "Windows ICS rejected COM automation (0x80040201)."
        Write-Host "Network Connections is being opened."
        Write-Host "Open Wi-Fi > Properties > Sharing, enable sharing,"
        Write-Host "then select: $TapAdapter"
        Start-Process -FilePath "control.exe" -ArgumentList "ncpa.cpl"
        exit 3
    }
    throw
}
Restart-Service -Name SharedAccess -Force
Start-Sleep -Seconds 5

$address = Get-NetIPAddress -InterfaceIndex $tap.ifIndex -AddressFamily IPv4 `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "169.254.*" } |
    Select-Object -First 1

Write-Host "ORYVAEL TAP network configured"
Write-Host "  public  $PublicAdapter"
Write-Host "  private $TapAdapter"
if ($null -ne $address) {
    Write-Host "  host IP $($address.IPAddress)/$($address.PrefixLength)"
} else {
    throw "ICS did not assign an IPv4 address to '$TapAdapter'."
}
