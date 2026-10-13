#Requires -Version 5.1
<#
.SYNOPSIS
    Trusts the RD Web feed certificate for the signed-in user and refreshes the feed only if needed.

.DESCRIPTION
    Deploy this once from an RMM tool. The tool runs it elevated from %TEMP%.
    On that run the script copies itself to the computer application-data folder
    and registers a logon task. Later runs are the task, in the user session.

    Microsoft stores computer-wide application data in CSIDL_COMMON_APPDATA
    (%ProgramData%). The copy lives at:
      C:\ProgramData\RdsScripts\RDApp-TrustCert-RefreshFeed.ps1
    Administrators and SYSTEM have full control. Users have read and execute only,
    so a user can run it but cannot change it. Per-user logs go under
    %LOCALAPPDATA%\RdsScripts\logs.

    The logon task runs as the interactive user, not elevated. It compares the
    leaf certificate on FeedHost:443 with HKCU TrustedCertThumbprints. If the
    SHA-1 thumbprint is already there, it exits without changes. If not, it adds
    the thumbprint and refreshes RemoteApp and Desktop Connections.

    Uses .NET Framework 4.6.2-compatible calls so stock Windows 11 and Windows
    PowerShell 5.1 can run it. FeedHost is required. There is no default host.

.PARAMETER FeedHost
    RD Web feed host. Required. No default.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RDApp-TrustCert-RefreshFeed.ps1 -FeedHost rd.contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $FeedHost
)

$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:ProgramData 'RdsScripts'
$InstallPath = Join-Path $InstallDir 'RDApp-TrustCert-RefreshFeed.ps1'
$TaskPath = '\RdsScripts\'
$TaskName = 'RDApp TrustCert RefreshFeed'

function Write-Log {
    param([string] $Message)
    $dir = Join-Path $env:LOCALAPPDATA 'RdsScripts\logs'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path (Join-Path $dir 'webfeed-trust.log') -Value $line
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-UsersReadOnlyAcl {
    param([string] $Path)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    foreach ($pair in @(
            @{ Id = 'BUILTIN\Administrators'; Rights = 'FullControl' },
            @{ Id = 'NT AUTHORITY\SYSTEM'; Rights = 'FullControl' },
            @{ Id = 'BUILTIN\Users'; Rights = 'ReadAndExecute' }
        )) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($pair.Id, $pair.Rights, $inherit, $none, 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Install-UserLogonTask {
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $InstallPath -Force
    Set-UsersReadOnlyAcl -Path $InstallDir

    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$InstallPath`" -FeedHost $FeedHost"
    $action = New-ScheduledTaskAction -Execute $ps -Argument $args
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Output "Installed $InstallPath"
    Write-Output "Logon task: $TaskPath$TaskName"
}

function Start-TaskForSignedInUsers {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$InstallPath`" -FeedHost $FeedHost"
    $explorer = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe'" -ErrorAction SilentlyContinue
    $accounts = @()
    foreach ($process in $explorer) {
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
        if (-not $owner -or $owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace($owner.User)) { continue }
        if ($owner.Domain -eq 'NT AUTHORITY' -or $owner.User -eq 'SYSTEM') { continue }
        $account = if ([string]::IsNullOrWhiteSpace($owner.Domain)) { $owner.User } else { '{0}\{1}' -f $owner.Domain, $owner.User }
        $accounts += $account
    }
    foreach ($account in @($accounts | Select-Object -Unique)) {
        $once = "$TaskName Once"
        $action = New-ScheduledTaskAction -Execute $ps -Argument $args
        $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $once -TaskPath $TaskPath -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskPath $TaskPath -TaskName $once
        Write-Output "Started user run for $account"
    }
}

function Get-FeedCertificate {
    param([string] $Name)
    $tcp = New-Object System.Net.Sockets.TcpClient
    $ssl = $null
    try {
        $tcp.Connect($Name, 443)
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $certificate, $chain, $errors)
            return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
        $ssl.AuthenticateAsClient($Name)
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
    }
    finally {
        if ($ssl) { $ssl.Close() }
        if ($tcp) { $tcp.Close() }
    }
}

function Get-Sha256Thumbprint {
    param($Certificate)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Certificate.RawData)
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToUpperInvariant()
    }
    finally {
        $sha.Clear()
    }
}

function Update-CurrentUserFeed {
    try {
        $cert = Get-FeedCertificate -Name $FeedHost
    }
    catch {
        Write-Log "ERROR reading certificate from ${FeedHost}:443 - $($_.Exception.Message)"
        Write-Error "Could not read the certificate from ${FeedHost}:443. $($_.Exception.Message)"
        exit 3
    }

    $sha1 = $cert.Thumbprint.ToUpperInvariant()
    $sha256Token = 'sha256:' + (Get-Sha256Thumbprint -Certificate $cert)
    $policyKey = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $existing = $null
    if (Test-Path $policyKey) {
        $existing = (Get-ItemProperty -Path $policyKey -Name TrustedCertThumbprints -ErrorAction SilentlyContinue).TrustedCertThumbprints
    }
    $tokens = @()
    if ($existing) {
        $tokens = @($existing -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    if ($tokens -contains $sha1) {
        Write-Log "Thumbprint $sha1 already in HKCU TrustedCertThumbprints. No changes."
        exit 0
    }

    Write-Log "Thumbprint $sha1 missing from HKCU TrustedCertThumbprints. Updating and refreshing feed."
    if (-not (Test-Path $policyKey)) { New-Item -Path $policyKey -Force | Out-Null }
    foreach ($item in @($sha1, $sha256Token)) {
        if ($tokens -notcontains $item) { $tokens += $item }
    }
    New-ItemProperty -Path $policyKey -Name TrustedCertThumbprints -PropertyType String -Value ($tokens -join ',') -Force | Out-Null
    $allow = (Get-ItemProperty -Path $policyKey -Name AllowSignedFiles -ErrorAction SilentlyContinue).AllowSignedFiles
    if ($allow -ne 1) {
        New-ItemProperty -Path $policyKey -Name AllowSignedFiles -PropertyType DWord -Value 1 -Force | Out-Null
    }

    $bypassKey = 'HKCU:\Software\Microsoft\Terminal Server Client\PublisherBypassList'
    if (-not (Test-Path $bypassKey)) { New-Item -Path $bypassKey -Force | Out-Null }
    New-ItemProperty -Path $bypassKey -Name $sha1 -PropertyType DWord -Value 0xFFFFFFFF -Force | Out-Null

    $feedUrl = 'https://{0}/RDWeb/Feed/webfeed.aspx' -f $FeedHost
    $subscribed = $false
    $feedsKey = 'HKCU:\Software\Microsoft\Workspaces\Feeds'
    if (Test-Path $feedsKey) {
        foreach ($feed in Get-ChildItem $feedsKey -ErrorAction SilentlyContinue) {
            $url = (Get-ItemProperty -Path $feed.PSPath -Name URL -ErrorAction SilentlyContinue).URL
            if ($url -and $url -match [regex]::Escape($FeedHost)) { $subscribed = $true; break }
        }
    }
    if (-not $subscribed) {
        $wcxDir = Join-Path $env:LOCALAPPDATA 'RdsScripts'
        if (-not (Test-Path $wcxDir)) { New-Item -ItemType Directory -Path $wcxDir -Force | Out-Null }
        $wcx = Join-Path $wcxDir ($FeedHost + '.wcx')
        @"
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<workspace name="RemoteApps" xmlns="http://schemas.microsoft.com/ts/2008/09/tswcx" xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <defaultFeed url="$feedUrl" />
</workspace>
"@ | Set-Content -Path $wcx -Encoding UTF8
        Write-Log "No subscription for $FeedHost. Running WorkspaceSilentSetup."
        Start-Process -FilePath "$env:SystemRoot\System32\rundll32.exe" -ArgumentList @('tsworkspace.dll,WorkspaceSilentSetup', $wcx) -Wait -WindowStyle Hidden | Out-Null
    }

    Write-Log 'Refreshing RemoteApp and Desktop Connections.'
    Start-Process -FilePath "$env:SystemRoot\System32\rundll32.exe" -ArgumentList 'tsworkspace.dll,TaskUpdateWorkspaces2' -Wait -WindowStyle Hidden | Out-Null
    Start-Process -FilePath "$env:SystemRoot\System32\rundll32.exe" -ArgumentList 'tsworkspace.dll,WorkspaceStatusNotify2' -WindowStyle Hidden | Out-Null
    Write-Log "Added $sha1 and refreshed feed."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($FeedHost)) {
    Write-Error 'FeedHost is required. Pass the RD Web feed host.'
    exit 2
}
$FeedHost = $FeedHost.Trim().TrimEnd('.')
if ($FeedHost -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$') {
    Write-Error "FeedHost '$FeedHost' is not a valid hostname."
    exit 2
}

if (Test-IsAdministrator) {
    Install-UserLogonTask
    Start-TaskForSignedInUsers
    exit 0
}

Update-CurrentUserFeed
