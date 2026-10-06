<#
.SYNOPSIS
    Liệt kê các GPO trong folder GPOs của Microsoft Security Baseline,
    map mỗi GUID với tên GPO và object tương ứng (Computer / User).

.DESCRIPTION
    Đọc từng folder GUID trong folder GPOs, lấy tên GPO từ Backup.xml
    (fallback sang bkupInfo.xml), và xác định GPO cấu hình cho Machine
    (Computer) hay User, cùng các loại setting có trong đó.

.PARAMETER GposPath
    Đường dẫn tới folder GPOs của gói baseline.

.EXAMPLE
    .\List-BaselineGPOs.ps1 -GposPath "C:\Baseline\Windows 11 24H2\GPOs"

.EXAMPLE
    .\List-BaselineGPOs.ps1 "C:\Baseline\GPOs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$GposPath
)

if (-not (Test-Path -Path $GposPath -PathType Container)) {
    Write-Error "Khong tim thay folder: $GposPath"
    exit 1
}

function Get-GpoName {
    param([string]$GpoPath)

    # Uu tien Backup.xml
    $backup = Join-Path $GpoPath "Backup.xml"
    if (Test-Path $backup) {
        try {
            [xml]$x = Get-Content $backup -Encoding UTF8 -ErrorAction Stop
            $n = $x.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.'#cdata-section'
            if ($n) { return $n.Trim() }
        } catch {}
    }

    # Fallback bkupInfo.xml
    $bkupInfo = Join-Path $GpoPath "bkupInfo.xml"
    if (Test-Path $bkupInfo) {
        try {
            [xml]$x = Get-Content $bkupInfo -Encoding UTF8 -ErrorAction Stop
            $n = $x.BackupInst.GPODisplayName.'#cdata-section'
            if ($n) { return $n.Trim() }
        } catch {}
    }

    return "(khong doc duoc ten)"
}

$results = Get-ChildItem -Path $GposPath -Directory | ForEach-Object {
    $gpoPath = $_.FullName

    $machinePol = Join-Path $gpoPath "DomainSysvol\GPO\Machine\registry.pol"
    $userPol    = Join-Path $gpoPath "DomainSysvol\GPO\User\registry.pol"
    $secInf     = Join-Path $gpoPath "DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
    $auditCsv   = Join-Path $gpoPath "DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv"

    $objects = @()
    if (Test-Path $machinePol) { $objects += "Computer" }
    if (Test-Path $userPol)    { $objects += "User" }

    $settings = @()
    if (Test-Path $machinePol) { $settings += "Registry(Machine)" }
    if (Test-Path $userPol)    { $settings += "Registry(User)" }
    if (Test-Path $secInf)     { $settings += "SecurityTemplate" }
    if (Test-Path $auditCsv)   { $settings += "AdvancedAudit" }

    [PSCustomObject]@{
        GPOName  = Get-GpoName -GpoPath $gpoPath
        GUID     = $_.Name
        Objects  = ($objects  -join ", ")
        Settings = ($settings -join ", ")
    }
}

$results | Sort-Object GPOName | Format-Table -AutoSize -Wrap
Write-Host ""
Write-Host ("Tong cong: {0} GPO" -f $results.Count) -ForegroundColor Cyan