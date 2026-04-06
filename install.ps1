#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Sentari Agent — Windows installation script.

.DESCRIPTION
    Downloads, verifies, and installs the Sentari agent as a Windows service.

    This script:
      1. Downloads the agent binary from GitHub Releases
      2. Verifies the SHA256 checksum
      3. Installs the binary to C:\Program Files\Sentari\
      4. Creates the config file at C:\Program Files\Sentari\config\agent.conf
      5. Writes the enrollment token to a restricted file (not in config)
      6. Creates C:\ProgramData\Sentari\ with restricted ACLs (SYSTEM + Administrators)
      7. Registers a Windows service with auto-restart policy
      8. Starts the service
      9. Adds the install directory to the system PATH

.PARAMETER Version
    Agent version to install (e.g., 0.1.0). Required.

.PARAMETER ServerURL
    Sentari server URL (e.g., https://sentari.example.com:8000). Required.

.PARAMETER EnrollToken
    One-time enrollment token from the Sentari admin console. Required.

.PARAMETER Edition
    'enterprise' (default) or 'oss'.

.PARAMETER ScanInterval
    Time between scans in seconds. Default: 3600 (1 hour).

.PARAMETER InstallDir
    Installation directory. Default: C:\Program Files\Sentari

.PARAMETER ServiceName
    Windows service name. Default: SentariAgent

.EXAMPLE
    .\install.ps1 -Version 0.1.0 -ServerURL https://sentari.example.com:8000 -EnrollToken abc123

.EXAMPLE
    irm https://raw.githubusercontent.com/sentari-dev/sentari-agent/main/install.ps1 -OutFile install.ps1
    .\install.ps1 -Version 0.1.0 -ServerURL https://sentari.example.com:8000 -EnrollToken abc123 -Edition oss
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https?://')]
    [string]$ServerURL,

    [Parameter(Mandatory = $true)]
    [string]$EnrollToken,

    [Parameter(Mandatory = $false)]
    [ValidateSet('enterprise', 'oss')]
    [string]$Edition = 'enterprise',

    [Parameter(Mandatory = $false)]
    [ValidateRange(60, 86400)]
    [int]$ScanInterval = 3600,

    [Parameter(Mandatory = $false)]
    [string]$InstallDir = 'C:\Program Files\Sentari',

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = 'SentariAgent'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GitHubRepo = 'sentari-dev/sentari-agent'

# =============================================================================
# Helpers
# =============================================================================

function Stop-WithError {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit 1
}

# =============================================================================
# Banner
# =============================================================================

Write-Host ''
Write-Host '============================================' -ForegroundColor Cyan
Write-Host '  Sentari Agent Installer (Windows)' -ForegroundColor Cyan
Write-Host '============================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Version:    v$Version"
Write-Host "  Edition:    $Edition"
Write-Host "  OS/Arch:    windows/amd64"
Write-Host "  Server:     $ServerURL"
Write-Host ''

# =============================================================================
# [1/9] Check prerequisites
# =============================================================================

Write-Host '[1/9] Checking prerequisites...' -ForegroundColor Cyan

$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Stop-WithError "Windows 10 / Server 2016 or later is required (detected $osVersion)."
}

Write-Host '  OK -- Windows 10+ detected' -ForegroundColor Green

# =============================================================================
# [2/9] Download agent binary
# =============================================================================

Write-Host ''
Write-Host '[2/9] Downloading agent binary...' -ForegroundColor Cyan

if ($Edition -eq 'oss') {
    $BinaryFile = "sentari-agent-oss-windows-amd64.exe"
} else {
    $BinaryFile = "sentari-agent-windows-amd64.exe"
}

$DownloadURL = "https://github.com/$GitHubRepo/releases/download/v$Version/$BinaryFile"
$ChecksumsURL = "https://github.com/$GitHubRepo/releases/download/v$Version/SHA256SUMS.txt"

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "sentari-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $TempBinary = Join-Path $TempDir $BinaryFile
    $TempChecksums = Join-Path $TempDir 'SHA256SUMS.txt'

    Write-Host "  Downloading $BinaryFile..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $DownloadURL -OutFile $TempBinary -UseBasicParsing
    } catch {
        Stop-WithError "Failed to download from $DownloadURL`nCheck that version v$Version exists at: https://github.com/$GitHubRepo/releases"
    }

    Write-Host "  Downloading SHA256SUMS.txt..."
    $checksumVerified = $false
    try {
        Invoke-WebRequest -Uri $ChecksumsURL -OutFile $TempChecksums -UseBasicParsing
        $checksumVerified = $true
    } catch {
        Write-Host '  Warning: Could not download checksums -- skipping verification' -ForegroundColor Yellow
    }

    # =========================================================================
    # [3/9] Verify checksum
    # =========================================================================

    if ($checksumVerified) {
        Write-Host ''
        Write-Host '[3/9] Verifying checksum...' -ForegroundColor Cyan

        $expectedLine = Get-Content $TempChecksums | Where-Object { $_ -match [regex]::Escape($BinaryFile) }
        if (-not $expectedLine) {
            Stop-WithError "Binary '$BinaryFile' not found in SHA256SUMS.txt."
        }

        $expectedHash = ($expectedLine -split '\s+')[0].Trim().ToUpper()
        $actualHash = (Get-FileHash -Path $TempBinary -Algorithm SHA256).Hash.ToUpper()

        if ($actualHash -ne $expectedHash) {
            Stop-WithError "Checksum verification FAILED.`nExpected: $expectedHash`nActual:   $actualHash`nThe downloaded binary does not match the expected checksum."
        }

        Write-Host '  OK -- checksum verified' -ForegroundColor Green
    } else {
        Write-Host ''
        Write-Host '[3/9] Skipping checksum verification (no checksums available)' -ForegroundColor Yellow
    }

    # =========================================================================
    # [4/9] Stop existing service if upgrading
    # =========================================================================

    Write-Host ''
    Write-Host '[4/9] Installing binary...' -ForegroundColor Cyan

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $existingService) {
        Write-Host "  Existing service '$ServiceName' found -- stopping for upgrade..."
        if ($existingService.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force
        }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
        Write-Host '  Old service removed.' -ForegroundColor Green
    }

    # Install binary
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $destBinary = Join-Path $InstallDir 'sentari-agent.exe'
    Copy-Item -Path $TempBinary -Destination $destBinary -Force
    Write-Host "  Installed: $destBinary" -ForegroundColor Green

    # =========================================================================
    # [5/9] Create configuration
    # =========================================================================

    Write-Host ''
    Write-Host '[5/9] Creating configuration...' -ForegroundColor Cyan

    $configDir = Join-Path $InstallDir 'config'
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    $configFile = Join-Path $configDir 'agent.conf'
    $timestamp = Get-Date -Format 'o'

    $configContent = @"
# Sentari Agent Configuration
# Generated by install.ps1 on $timestamp

[server]
url = $ServerURL

[scanner]
scan_root = C:\
max_depth = 12
interval = $ScanInterval
"@

    Set-Content -Path $configFile -Value $configContent -Encoding UTF8
    Write-Host "  Config:  $configFile" -ForegroundColor Green

    # Write enrollment token to a separate restricted file (not in config,
    # not visible on the command line via process listing).
    $tokenFile = Join-Path $configDir 'enroll-token'
    Set-Content -Path $tokenFile -Value $EnrollToken -NoNewline -Encoding UTF8

    # Restrict enroll-token to SYSTEM + Administrators only.
    $tokenAcl = Get-Acl $tokenFile
    $tokenAcl.SetAccessRuleProtection($true, $false)
    $tokenSystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'None', 'None', 'Allow'
    )
    $tokenAdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'None', 'None', 'Allow'
    )
    $tokenAcl.AddAccessRule($tokenSystemRule)
    $tokenAcl.AddAccessRule($tokenAdminRule)
    Set-Acl -Path $tokenFile -AclObject $tokenAcl
    Write-Host "  Token:   $tokenFile (restricted ACL)" -ForegroundColor Green

    # =========================================================================
    # [6/9] Create data directory with restricted ACLs
    # =========================================================================

    Write-Host ''
    Write-Host '[6/9] Creating data directory...' -ForegroundColor Cyan

    $dataDir = 'C:\ProgramData\Sentari'
    if (-not (Test-Path $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    }

    # Restrict to SYSTEM + Administrators only (remove inherited permissions).
    $acl = Get-Acl $dataDir
    $acl.SetAccessRuleProtection($true, $false)
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
    )
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
    )
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $dataDir -AclObject $acl
    Write-Host "  Data:    $dataDir (SYSTEM + Administrators only)" -ForegroundColor Green

    # =========================================================================
    # [7/9] Register Windows service
    # =========================================================================

    Write-Host ''
    Write-Host '[7/9] Registering Windows service...' -ForegroundColor Cyan

    $serviceBinaryPath = "`"$destBinary`" --serve --config `"$configFile`" --enroll-token-file `"$tokenFile`" --data-dir `"$dataDir`""

    New-Service `
        -Name $ServiceName `
        -BinaryPathName $serviceBinaryPath `
        -DisplayName 'Sentari Agent' `
        -Description 'Sentari Python package inventory agent. Scans installed packages and reports to the Sentari server.' `
        -StartupType Automatic | Out-Null

    # Configure service recovery: restart on first, second, and subsequent failures.
    # Reset failure counter after 1 day (86400 seconds).
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    Write-Host "  Service: $ServiceName (Automatic start, auto-restart on failure)" -ForegroundColor Green

    # =========================================================================
    # [8/9] Start the service
    # =========================================================================

    Write-Host ''
    Write-Host '[8/9] Starting the agent...' -ForegroundColor Cyan

    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2

    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq 'Running') {
        Write-Host '  OK -- sentari-agent is running' -ForegroundColor Green
    } else {
        Write-Host "  Warning: Service status is '$($svc.Status)'. Check Event Viewer for details." -ForegroundColor Yellow
    }

    # =========================================================================
    # [9/9] Add install directory to system PATH
    # =========================================================================

    Write-Host ''
    Write-Host '[9/9] Updating system PATH...' -ForegroundColor Cyan

    $machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
    if ($machinePath -notlike "*$InstallDir*") {
        [System.Environment]::SetEnvironmentVariable('Path', "$machinePath;$InstallDir", 'Machine')
        Write-Host "  Added $InstallDir to system PATH" -ForegroundColor Green
    } else {
        Write-Host "  $InstallDir already in PATH" -ForegroundColor Green
    }

} finally {
    # Clean up temp directory
    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
    }
}

# =============================================================================
# Summary
# =============================================================================

Write-Host ''
Write-Host '============================================' -ForegroundColor Cyan
Write-Host '  Installation complete!' -ForegroundColor Cyan
Write-Host '============================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Binary:   $destBinary"
Write-Host "  Config:   $configFile"
Write-Host "  Token:    $tokenFile"
Write-Host "  Data:     $dataDir"
Write-Host "  Service:  $ServiceName"
Write-Host ''
Write-Host '  Useful commands:' -ForegroundColor Yellow
Write-Host "    Get-Service $ServiceName                   # Check status"
Write-Host "    Get-EventLog -LogName Application -Source $ServiceName  # View logs"
Write-Host "    Restart-Service $ServiceName               # Restart"
Write-Host "    Stop-Service $ServiceName                  # Stop"
Write-Host ''
Write-Host "  The agent will register with the server on its first scan"
Write-Host "  and then scan every $ScanInterval seconds."
Write-Host ''
