#Requires -Version 5.1
<#
    Apply-Baseline.ps1
    ------------------
    Chay phien audit baseline Windows: chup cau hinh GPO ra .PolicyRules bang
    LGPO.exe + GPO2PolicyRules.exe, kiem tra security stack bang script, va
    (tuy chon) ap baseline bang LGPO /p.

    Cau truc thu muc mong doi (dat script ngang hang voi cac thu muc nay):
        .\LGPO\LGPO.exe
        .\PolicyAnalyzer\GPO2PolicyRules.exe
        .\policy_rules\*.PolicyRules
        .\Apply-Baseline.ps1

    Audit khong xong trong 1 lan chay: lan dau lay hien trang, sau do nguoi lam
    audit sua cau hinh thu cong (onboard MDE, cai Wazuh/Sysmon, bat command
    logging...), roi chay lai voi -Recheck de xac nhan. Vi vay co 2 che do:

      LAN DAU (khong co -Recheck) - tao folder audit_<BASE>\ moi:
        [1] SNAPSHOT : chup policy hien tai -> pre_<BASE>.PolicyRules
        [2] CHECK    : script check security stack -> pre_scriptcheck_<BASE>.txt
        [3] REMEDIATE: LGPO /p (co xac nhan y/N)   -> lgpo.out + lgpo.err
                       KHONG chup post_<BASE>.PolicyRules o buoc nay.

      RECHECK (-Recheck) - chon 1 folder audit_* co san, dung lai <BASE> cu:
        [1] SNAPSHOT : chup policy hien tai -> post_<BASE>.PolicyRules
        [2] CHECK    : script check security stack -> post_scriptcheck_<BASE>.txt
        Khong chay REMEDIATE. File cu bi GHI DE.

    Folder ket qua chua toi da 4 file bao cao + 2 file log cua LGPO:
        pre_<BASE>.PolicyRules        policy TRUOC khi co tac dong
        pre_scriptcheck_<BASE>.txt    security stack TRUOC khi co tac dong
        post_<BASE>.PolicyRules       policy sau khi recheck
        post_scriptcheck_<BASE>.txt   security stack sau khi recheck
        lgpo.out / lgpo.err           stdout/stderr cua "LGPO /p" (chi khi remediate)
    Chi audit (khong remediate, khong recheck) -> chi co 2 file pre_*.

    So sanh truoc/sau: mo Policy Analyzer -> Add 2 file .PolicyRules -> View/Compare.

    Tham so:
        -Recheck (hoac --recheck)  chon folder audit_* co san, gen lai bo file post_*

    Yeu cau: chay bang quyen Administrator.
#>

[CmdletBinding()]
param(
    [switch]$Recheck,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = 'Stop'

# ============================================================
# 0. Doc tham so kieu Linux (--recheck) cho dong bo voi audit.sh
# ============================================================
if ($ExtraArgs) {
    foreach ($a in $ExtraArgs) {
        switch -Regex ($a) {
            '^--recheck$'  { $Recheck = $true }
            '^(--help|-h)$' {
                Write-Host "Usage: .\Apply-Baseline.ps1 [-Recheck | --recheck]"
                Write-Host ""
                Write-Host "  (no flag)   First run: create a new audit_<BASE>\ folder, produce"
                Write-Host "              pre_<BASE>.PolicyRules and pre_scriptcheck_<BASE>.txt,"
                Write-Host "              then optionally apply the baseline (lgpo.out / lgpo.err)."
                Write-Host "  -Recheck    Pick an existing audit_* folder and re-verify the machine."
                Write-Host "              Regenerates post_<BASE>.PolicyRules and"
                Write-Host "              post_scriptcheck_<BASE>.txt, OVERWRITING them if present."
                Write-Host "              The baseline is not applied."
                exit 0
            }
            default {
                Write-Host "[ERROR] Unknown argument: $a" -ForegroundColor Red
                Write-Host "        Run with --help to see the usage." -ForegroundColor Red
                exit 1
            }
        }
    }
}

# ============================================================
# 1. Cau hinh duong dan (theo $PSScriptRoot)
# ============================================================
$ScriptRoot     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LgpoExe        = Join-Path $ScriptRoot 'LGPO\LGPO.exe'
$Gpo2RulesExe   = Join-Path $ScriptRoot 'PolicyAnalyzer\GPO2PolicyRules.exe'
$PolicyRulesDir = Join-Path $ScriptRoot 'policy_rules'

# ============================================================
# 2. Kiem tra dieu kien tien quyet
# ============================================================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

foreach ($tool in @(@{P=$LgpoExe;N='LGPO.exe'}, @{P=$Gpo2RulesExe;N='GPO2PolicyRules.exe'})) {
    if (-not (Test-Path $tool.P)) {
        Write-Host "[ERROR] $($tool.N) not found at: $($tool.P)" -ForegroundColor Red
        if ($tool.N -eq 'GPO2PolicyRules.exe') {
            Write-Host "        GPO2PolicyRules.exe ships with Policy Analyzer (next to PolicyAnalyzer.exe)." -ForegroundColor Red
        }
        exit 1
    }
}

# policy_rules chi can khi ap baseline -> che do recheck khong bat buoc
if ((-not $Recheck) -and (-not (Test-Path $PolicyRulesDir))) {
    Write-Host "[ERROR] policy_rules folder not found at: $PolicyRulesDir" -ForegroundColor Red
    exit 1
}

# ============================================================
# 3. Ham dung chung
# ============================================================
function Read-NonEmpty([string]$Prompt) {
    do {
        $v = (Read-Host $Prompt).Trim()
        if ([string]::IsNullOrWhiteSpace($v)) {
            Write-Host "    Value must not be empty. Please try again." -ForegroundColor Yellow
        }
    } until (-not [string]::IsNullOrWhiteSpace($v))
    return $v
}

function Read-IPAddress([string]$Prompt) {
    do {
        $v = (Read-Host $Prompt).Trim()
        $parsed = $null
        $ok = [System.Net.IPAddress]::TryParse($v, [ref]$parsed)
        if (-not $ok) {
            Write-Host "    Invalid IP address. Example: 10.20.30.40. Please try again." -ForegroundColor Yellow
        }
    } until ($ok)
    return $v
}

function Select-FromList {
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string[]]$Items)
    Write-Host $Title -ForegroundColor Cyan
    for ($i = 0; $i -lt $Items.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $Items[$i])
    }
    do {
        $sel = (Read-Host ("Select a number [1-{0}]" -f $Items.Count)).Trim()
        $valid = ($sel -match '^\d+$') -and ([int]$sel -ge 1) -and ([int]$sel -le $Items.Count)
        if (-not $valid) { Write-Host "    Invalid choice, please try again." -ForegroundColor Yellow }
    } until ($valid)
    return $Items[[int]$sel - 1]
}

function Format-Token([string]$s) {
    return ($s -replace '[\\/:*?"<>|\s]', '-')
}

# ============================================================
# Ham chay 1 exe. Neu co -StdoutFile/-StderrFile thi giu lai, khong thi
# dung file tam roi xoa (chi hien thi ra man hinh).
# Dung Start-Process + redirect ra file de tranh NativeCommandError (mau do gia).
# ============================================================
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$StdoutFile,
        [string]$StderrFile,
        [string]$Step = 'RUN'
    )
    Write-Host "[$Step] $([IO.Path]::GetFileName($Exe)) $($Arguments -join ' ')" -ForegroundColor DarkGray

    $argLine = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '

    $outTarget = if ($StdoutFile) { $StdoutFile } else { [IO.Path]::GetTempFileName() }
    $errTarget = if ($StderrFile) { $StderrFile } else { [IO.Path]::GetTempFileName() }

    $code = 1
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $argLine -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $outTarget -RedirectStandardError $errTarget
        $code = $p.ExitCode
    } catch {
        Write-Host "[$Step] Cannot run $Exe : $($_.Exception.Message)" -ForegroundColor Red
    }

    foreach ($f in @($outTarget, $errTarget)) {
        if (Test-Path $f) {
            $c = Get-Content -LiteralPath $f
            if ($c) { $c | Out-Host }
        }
    }

    if (-not $StdoutFile) { Remove-Item $outTarget -Force -ErrorAction SilentlyContinue }
    if (-not $StderrFile) { Remove-Item $errTarget -Force -ErrorAction SilentlyContinue }

    if ($code -ne 0) {
        Write-Host "[$Step] Exit code $code" -ForegroundColor Yellow
    }
    return $code
}

# Chay 1 exe va tra ve TOAN BO output (stdout + stderr) duoi dang chuoi.
# Dung cho cac lenh can doc ket qua nhu "Sysmon64 -c", "auditpol /get".
function Get-NativeOutput {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    $out = [IO.Path]::GetTempFileName()
    $err = [IO.Path]::GetTempFileName()
    $text = ''
    try {
        $argLine = ($Arguments | ForEach-Object {
            if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
        }) -join ' '
        Start-Process -FilePath $Exe -ArgumentList $argLine -NoNewWindow -Wait `
            -RedirectStandardOutput $out -RedirectStandardError $err | Out-Null
        $o = Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue
        $e = Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue
        $text = "$o`n$e"
    } catch {
        $text = ''
    } finally {
        Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
    }
    return $text
}

# ============================================================
# Chup snapshot local policy ra 1 file .PolicyRules
#   1) LGPO /b -> GPO backup (thu muc tam trong %TEMP%)
#   2) GPO2PolicyRules.exe -> file .PolicyRules
#   3) xoa thu muc tam (khong ghi log file cho buoc nay)
# ============================================================
function New-PolicyRulesSnapshot {
    param(
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Step
    )
    # GPO2PolicyRules khong ghi de file co san -> xoa truoc cho chac
    if (Test-Path -LiteralPath $OutFile) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    }

    $tmp = Join-Path $env:TEMP ("lgpo_snap_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null

    $code = 1
    try {
        Invoke-Native -Exe $LgpoExe      -Arguments @('/b', $tmp, '/n', $DisplayName, '/v') -Step "$Step-BACKUP"  | Out-Null
        $code = Invoke-Native -Exe $Gpo2RulesExe -Arguments @($tmp, $OutFile)                       -Step "$Step-CONVERT"
    } finally {
        Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $OutFile) {
        Write-Host "  -> Created: $OutFile" -ForegroundColor Green
    } else {
        Write-Host "  -> [WARNING] Could not create $OutFile" -ForegroundColor Yellow
    }
    return $code
}

# ============================================================
# 4. Xac dinh folder ket qua + <BASE>
#    - Lan dau : hoi ma nhan vien / IP -> tao folder audit_<BASE> moi
#    - -Recheck: chon 1 folder audit_* co san -> DUNG LAI <BASE> cu
#      (bat buoc dung lai BASE cu de bo file post_* trung ten voi bo pre_*)
# ============================================================
if ($Recheck) {
    $dirs = @(Get-ChildItem -LiteralPath $ScriptRoot -Directory -Filter 'audit_*' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending)
    if ($dirs.Count -eq 0) {
        Write-Host "[ERROR] No audit_* folder found in $ScriptRoot" -ForegroundColor Red
        Write-Host "        Run the script without -Recheck first to create one." -ForegroundColor Red
        exit 1
    }

    Write-Host "==== SELECT AUDIT FOLDER TO RECHECK ====" -ForegroundColor Cyan
    $dirName  = Select-FromList -Title "Audit folders (newest first):" -Items ($dirs | ForEach-Object { $_.Name })
    $AuditDir = Join-Path $ScriptRoot $dirName
    $Tag      = $dirName -replace '^audit_', ''

    # Tach lai hostname / IP / ma nhan vien tu <BASE> de ghi vao header report.
    # BASE = <hostname>_<ip>_<yyyyMMdd>_<HHmmss>_<ma nhan vien>
    # Neo vao khoi timestamp (8 so _ 6 so) nen hostname hoac ma nhan vien co
    # dau '_' o trong van tach dung.
    $Hostname = $env:COMPUTERNAME; $DeviceIp = '(unknown)'; $EmpCode = '(unknown)'
    if ($Tag -match '^(.*)_(\d{8})_(\d{6})_(.*)$') {
        $hostIp   = $Matches[1]
        $EmpCode  = $Matches[4]
        $cut      = $hostIp.LastIndexOf('_')
        if ($cut -gt 0) {
            $Hostname = $hostIp.Substring(0, $cut)
            $DeviceIp = $hostIp.Substring($cut + 1)
        } else {
            $Hostname = $hostIp
        }
    } else {
        Write-Host "[WARNING] Folder name does not look like <hostname>_<ip>_<timestamp>_<employee>;" -ForegroundColor Yellow
        Write-Host "          report header fields will be read from this machine instead." -ForegroundColor Yellow
    }

    # Canh bao neu folder khong phai cua phien audit nao, hoac cua may khac
    if (-not (Test-Path -LiteralPath (Join-Path $AuditDir ("pre_" + $Tag + ".PolicyRules")))) {
        Write-Host "[WARNING] pre_$Tag.PolicyRules not found in $dirName - is this really an audit folder?" -ForegroundColor Yellow
    }
    if ($Hostname -ne $env:COMPUTERNAME) {
        Write-Host "[WARNING] Folder belongs to host '$Hostname' but this machine is '$env:COMPUTERNAME'." -ForegroundColor Yellow
    }

    Write-Host "==> Recheck mode, reusing result folder: $dirName" -ForegroundColor Green
} else {
    Write-Host "==== AUDIT IDENTIFICATION ====" -ForegroundColor Cyan
    $EmpCode  = Read-NonEmpty  "Enter employee ID"
    $DeviceIp = Read-IPAddress "Enter device IP address"

    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $Hostname  = $env:COMPUTERNAME
    $Tag = '{0}_{1}_{2}_{3}' -f (Format-Token $Hostname), (Format-Token $DeviceIp), $Timestamp, (Format-Token $EmpCode)

    $AuditDir = Join-Path $ScriptRoot ("audit_" + $Tag)
    New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null
    Write-Host "==> Created result folder: $AuditDir" -ForegroundColor Green
}

# ============================================================
# 5. Tien to file output: pre_ (lan dau) hoac post_ (recheck)
# ============================================================
if ($Recheck) { $Phase = 'post' } else { $Phase = 'pre' }
$SnapshotFile = Join-Path $AuditDir ($Phase + "_" + $Tag + ".PolicyRules")
$ReportPath   = Join-Path $AuditDir ($Phase + "_scriptcheck_" + $Tag + ".txt")

Write-Host ""
Write-Host "======================================================================"
Write-Host " SELECTION"
Write-Host "======================================================================"
if ($Recheck) {
    Write-Host "  mode        = RECHECK (regenerate post_* files)"
} else {
    Write-Host "  mode        = FIRST RUN (create pre_* files)"
}
Write-Host "  hostname    = $Hostname"
Write-Host "  ip          = $DeviceIp"
Write-Host "  employee    = $EmpCode"
Write-Host "  results     = $AuditDir"
Write-Host ("  outputs     = {0}" -f [IO.Path]::GetFileName($SnapshotFile))
Write-Host ("                {0}" -f [IO.Path]::GetFileName($ReportPath))
if ($Recheck) {
    foreach ($f in @($SnapshotFile, $ReportPath)) {
        if (Test-Path -LiteralPath $f) {
            Write-Host ("  NOTE: {0} already exists and WILL BE OVERWRITTEN." -f [IO.Path]::GetFileName($f)) -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# ============================================================
# 6. Chon baseline .PolicyRules (chi khi KHONG recheck)
#    Chon truoc, roi moi chup snapshot -> snapshot phan anh dung hien trang
#    ngay truoc khi ap baseline da chon.
# ============================================================
$Chosen = $null
if (-not $Recheck) {
    $Rules = @(Get-ChildItem -Path $PolicyRulesDir -Filter '*.PolicyRules' -File | Sort-Object Name)
    if ($Rules.Count -eq 0) {
        Write-Host "[ERROR] No .PolicyRules file found in: $PolicyRulesDir" -ForegroundColor Red
        exit 1
    }
    Write-Host "==== SELECT BASELINE TO APPLY ====" -ForegroundColor Cyan
    $chosenName = Select-FromList -Title "Available baselines:" -Items ($Rules | ForEach-Object { $_.Name })
    $Chosen = $Rules | Where-Object { $_.Name -eq $chosenName } | Select-Object -First 1
    Write-Host "Selected: $($Chosen.Name)" -ForegroundColor Green
    Write-Host ""
}

# ============================================================
# 7. [1] SNAPSHOT policy hien tai
# ============================================================
Write-Host "======================================================================"
if ($Recheck) {
    Write-Host " [1] POLICY SNAPSHOT (recheck, after manual fixes)"
} else {
    Write-Host " [1] POLICY SNAPSHOT (before any change - backup)"
}
Write-Host "======================================================================"
New-PolicyRulesSnapshot -OutFile $SnapshotFile -DisplayName ($Phase + "_" + $Tag) -Step $Phase.ToUpper() | Out-Null
Write-Host ""

# ==================================================================
# 8. [2] SCRIPT CHECK security stack (Wazuh / MDE / Sysmon / command logging)
# ==================================================================
$script:CntPass = 0
$script:CntFail = 0
$script:CntWarn = 0
$script:CntSkip = 0
$script:FailedList = New-Object System.Collections.Generic.List[string]
$script:ReportPath = $ReportPath

# --- ghi 1 dong vao report + man hinh ---
function Write-ReportLine {
    param([string]$Text = '', [string]$Color = 'Gray')
    Add-Content -LiteralPath $script:ReportPath -Value $Text -Encoding utf8
    if ($Text -eq '') { Write-Host '' } else { Write-Host $Text -ForegroundColor $Color }
}

# Add-Result <PASS|FAIL|WARN|SKIP> <ID> <TIEU DE> [<CHI TIET>]
function Add-Result {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','WARN','SKIP')][string]$Status,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = ''
    )
    $color = 'Gray'
    switch ($Status) {
        'PASS' { $script:CntPass++; $color = 'Green' }
        'FAIL' { $script:CntFail++; $color = 'Red'
                 $script:FailedList.Add("$Id - $Title :: $Detail") | Out-Null }
        'WARN' { $script:CntWarn++; $color = 'Yellow' }
        'SKIP' { $script:CntSkip++; $color = 'DarkGray' }
    }
    Write-ReportLine -Text ('[ {0,-4} ] {1,-9} {2,-52} | {3}' -f $Status, $Id, $Title, $Detail) -Color $color
}

function Write-Section([string]$Title) {
    Write-ReportLine
    Write-ReportLine -Text ("--- " + $Title) -Color 'Cyan'
    Write-ReportLine -Text ('-' * 70) -Color 'Cyan'
}

# --- doc thong tin 1 service qua CIM (State / StartMode / PathName) ---
function Get-SvcCim([string]$Name) {
    return Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Name) -ErrorAction SilentlyContinue
}

# Test-SvcAspect: Installed | Automatic | Running
function Test-SvcAspect {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][ValidateSet('Installed','Automatic','Running')][string]$Aspect
    )
    $cim = Get-SvcCim $ServiceName
    if (-not $cim) {
        if ($Aspect -eq 'Installed') {
            Add-Result -Status FAIL -Id $Id -Title $Title -Detail ("service '{0}' not found" -f $ServiceName)
        } else {
            Add-Result -Status SKIP -Id $Id -Title $Title -Detail ("service '{0}' not installed" -f $ServiceName)
        }
        return
    }
    switch ($Aspect) {
        'Installed' {
            Add-Result -Status PASS -Id $Id -Title $Title -Detail ("installed: {0}" -f $cim.PathName)
        }
        'Automatic' {
            if ($cim.StartMode -eq 'Auto') {
                Add-Result -Status PASS -Id $Id -Title $Title -Detail ("StartMode={0}" -f $cim.StartMode)
            } else {
                Add-Result -Status FAIL -Id $Id -Title $Title -Detail ("StartMode={0}, expected Auto" -f $cim.StartMode)
            }
        }
        'Running' {
            if ($cim.State -eq 'Running') {
                Add-Result -Status PASS -Id $Id -Title $Title -Detail ("State={0}" -f $cim.State)
            } else {
                Add-Result -Status FAIL -Id $Id -Title $Title -Detail ("State={0}, expected Running" -f $cim.State)
            }
        }
    }
}

# --- tim pattern (regex, theo dong) trong danh sach file ---
function Test-PatternInFiles {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Pattern,
        [string[]]$Files
    )
    $existing = @()
    if ($Files) {
        $existing = @($Files | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) })
    }
    if ($existing.Count -eq 0) {
        Add-Result -Status SKIP -Id $Id -Title $Title -Detail 'no file available to check'
        return
    }
    foreach ($f in $existing) {
        $hit = Select-String -LiteralPath $f -Pattern $Pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) {
            Add-Result -Status PASS -Id $Id -Title $Title -Detail ("found in {0}" -f $f)
            return
        }
    }
    Add-Result -Status FAIL -Id $Id -Title $Title `
        -Detail ("pattern /{0}/ not found in {1} file(s): {2}" -f $Pattern, $existing.Count, ($existing[0]))
}

# --- doc 1 gia tri registry, tra ve $null neu khong co ---
function Get-RegValue([string]$Path, [string]$Name) {
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Test-RegValueIs {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Expected
    )
    $v = Get-RegValue -Path $Path -Name $Name
    if ($null -eq $v) {
        Add-Result -Status FAIL -Id $Id -Title $Title -Detail ("{0}\{1} is not set" -f $Path, $Name)
    } elseif ("$v" -eq "$Expected") {
        Add-Result -Status PASS -Id $Id -Title $Title -Detail ("{0}={1}" -f $Name, $v)
    } else {
        Add-Result -Status FAIL -Id $Id -Title $Title -Detail ("{0}={1}, expected {2}" -f $Name, $v, $Expected)
    }
}

# --- khoi tao report (ghi de file cu neu co) ---
if (Test-Path -LiteralPath $ReportPath) {
    Remove-Item -LiteralPath $ReportPath -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType File -Path $ReportPath -Force | Out-Null

Write-Host "======================================================================"
Write-Host " [2] SECURITY STACK CHECK (script) -> $ReportPath"
Write-Host "======================================================================"

$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($Recheck) { $phaseLabel = 'POST (recheck after fixes)' } else { $phaseLabel = 'PRE (initial audit)' }

Write-ReportLine -Text '======================================================================'
Write-ReportLine -Text ' SECURITY STACK BASELINE CHECK RESULTS'
Write-ReportLine -Text '======================================================================'
Write-ReportLine -Text (' Check phase   : {0}' -f $phaseLabel)
Write-ReportLine -Text (' Hostname      : {0}' -f $Hostname)
Write-ReportLine -Text (' IP (declared) : {0}' -f $DeviceIp)
Write-ReportLine -Text (' Employee ID   : {0}' -f $EmpCode)
Write-ReportLine -Text (' Timestamp     : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
if ($osInfo) {
    Write-ReportLine -Text (' Operating sys : {0} (build {1})' -f $osInfo.Caption, $osInfo.BuildNumber)
} else {
    Write-ReportLine -Text ' Operating sys : unknown'
}
Write-ReportLine -Text (' PowerShell    : {0}' -f $PSVersionTable.PSVersion.ToString())
Write-ReportLine -Text (' Run as        : {0} (elevated)' -f [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-ReportLine -Text '======================================================================'
Write-ReportLine -Text ' Status legend:'
Write-ReportLine -Text '   PASS = compliant | FAIL = non-compliant'
Write-ReportLine -Text '   WARN = partially compliant | SKIP = not applicable / cannot verify'
Write-ReportLine -Text '======================================================================'

# ================= 1) MDE (Microsoft Defender for Endpoint) =================
Write-Section "1) MDE - Microsoft Defender for Endpoint"
Test-SvcAspect -Id 'MDE-001' -Title 'Service Sense (MDE sensor) is installed'   -ServiceName 'Sense' -Aspect Installed
Test-SvcAspect -Id 'MDE-002' -Title 'Service Sense start type is Automatic'     -ServiceName 'Sense' -Aspect Automatic
Test-SvcAspect -Id 'MDE-003' -Title 'Service Sense is running'                  -ServiceName 'Sense' -Aspect Running

# Trang thai onboard MDE nam trong registry (1 = da onboard len tenant)
$atpStatus = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
$onboard   = Get-RegValue -Path $atpStatus -Name 'OnboardingState'
if ($null -eq $onboard) {
    Add-Result -Status FAIL -Id 'MDE-004' -Title 'MDE is onboarded to a tenant' -Detail 'OnboardingState registry value not found'
} elseif ("$onboard" -eq '1') {
    $orgId = Get-RegValue -Path $atpStatus -Name 'OrgId'
    if ($orgId) {
        Add-Result -Status PASS -Id 'MDE-004' -Title 'MDE is onboarded to a tenant' -Detail ("OnboardingState=1, OrgId={0}" -f $orgId)
    } else {
        Add-Result -Status PASS -Id 'MDE-004' -Title 'MDE is onboarded to a tenant' -Detail 'OnboardingState=1'
    }
} else {
    Add-Result -Status FAIL -Id 'MDE-004' -Title 'MDE is onboarded to a tenant' -Detail ("OnboardingState={0}, expected 1" -f $onboard)
}

# Trang thai RUNTIME cua Defender Antivirus - doc truc tiep, khong doan tu policy
$mp = $null
try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mp = $null }

if (-not $mp) {
    Add-Result -Status SKIP -Id 'MDE-005' -Title 'Real-time protection is enabled'      -Detail 'Get-MpComputerStatus not available'
    Add-Result -Status SKIP -Id 'MDE-006' -Title 'Tamper protection is enabled'         -Detail 'Get-MpComputerStatus not available'
    Add-Result -Status SKIP -Id 'MDE-007' -Title 'Defender AV is in active (not passive) mode' -Detail 'Get-MpComputerStatus not available'
} else {
    if ($mp.RealTimeProtectionEnabled) {
        Add-Result -Status PASS -Id 'MDE-005' -Title 'Real-time protection is enabled' -Detail 'RealTimeProtectionEnabled=True'
    } else {
        Add-Result -Status FAIL -Id 'MDE-005' -Title 'Real-time protection is enabled' -Detail 'RealTimeProtectionEnabled=False'
    }

    if ($mp.IsTamperProtected) {
        Add-Result -Status PASS -Id 'MDE-006' -Title 'Tamper protection is enabled' -Detail 'IsTamperProtected=True'
    } else {
        Add-Result -Status FAIL -Id 'MDE-006' -Title 'Tamper protection is enabled' -Detail 'IsTamperProtected=False'
    }

    # AMRunningMode: Normal / Passive / EDR Block Mode / SxS Passive Mode
    $mode = "$($mp.AMRunningMode)"
    if ($mode -eq 'Normal') {
        Add-Result -Status PASS -Id 'MDE-007' -Title 'Defender AV is in active (not passive) mode' -Detail ("AMRunningMode={0}" -f $mode)
    } elseif ($mode -like '*Passive*' -or $mode -like '*EDR Block*') {
        Add-Result -Status WARN -Id 'MDE-007' -Title 'Defender AV is in active (not passive) mode' -Detail ("AMRunningMode={0} (another AV is primary)" -f $mode)
    } else {
        Add-Result -Status WARN -Id 'MDE-007' -Title 'Defender AV is in active (not passive) mode' -Detail ("AMRunningMode={0}" -f $mode)
    }
}

# ============================ 2) WAZUH AGENT ================================
Write-Section "2) Wazuh agent"
Test-SvcAspect -Id 'WAZ-001' -Title 'Service WazuhSvc is installed'         -ServiceName 'WazuhSvc' -Aspect Installed
Test-SvcAspect -Id 'WAZ-002' -Title 'Service WazuhSvc start type is Automatic' -ServiceName 'WazuhSvc' -Aspect Automatic
Test-SvcAspect -Id 'WAZ-003' -Title 'Service WazuhSvc is running'           -ServiceName 'WazuhSvc' -Aspect Running

# Tim ossec.conf + file cau hinh theo group (shared\agent.conf)
$wazCandidates = @(
    (Join-Path ${env:ProgramFiles(x86)} 'ossec-agent\ossec.conf'),
    (Join-Path $env:ProgramFiles       'ossec-agent\ossec.conf'),
    'C:\Program Files (x86)\ossec-agent\ossec.conf',
    'C:\Program Files\ossec-agent\ossec.conf'
)
$OssecConf = $null
foreach ($c in $wazCandidates) {
    if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { $OssecConf = $c; break }
}

$WazFiles = @()
if ($OssecConf) {
    $WazFiles += $OssecConf
    $sharedDir = Join-Path (Split-Path -Parent $OssecConf) 'shared'
    if (Test-Path -LiteralPath $sharedDir) {
        $WazFiles += @(Get-ChildItem -LiteralPath $sharedDir -Filter '*.conf' -File -ErrorAction SilentlyContinue |
                       ForEach-Object { $_.FullName })
    }
}

if ($WazFiles.Count -eq 0) {
    foreach ($p in @(
        @{I='WAZ-004'; T='Wazuh reports to a configured manager address'},
        @{I='WAZ-005'; T='Wazuh collects the Security event channel'},
        @{I='WAZ-006'; T='Wazuh collects the Sysmon event channel'},
        @{I='WAZ-007'; T='Wazuh collects the PowerShell event channel'})) {
        Add-Result -Status SKIP -Id $p.I -Title $p.T -Detail 'ossec.conf not found'
    }
} else {
    # Manager address phai khac placeholder mac dinh (0.0.0.0 / MANAGER_IP)
    $addr = $null
    foreach ($f in $WazFiles) {
        $m = Select-String -LiteralPath $f -Pattern '<address>\s*([^<\s]+)\s*</address>' -ErrorAction SilentlyContinue |
             Select-Object -First 1
        if ($m) { $addr = $m.Matches[0].Groups[1].Value; break }
    }
    if (-not $addr) {
        Add-Result -Status FAIL -Id 'WAZ-004' -Title 'Wazuh reports to a configured manager address' -Detail 'no <address> element in ossec.conf'
    } elseif ($addr -eq '0.0.0.0' -or $addr -eq 'MANAGER_IP') {
        Add-Result -Status FAIL -Id 'WAZ-004' -Title 'Wazuh reports to a configured manager address' -Detail ("address={0} is still the install placeholder" -f $addr)
    } else {
        Add-Result -Status PASS -Id 'WAZ-004' -Title 'Wazuh reports to a configured manager address' -Detail ("address={0}" -f $addr)
    }

    Test-PatternInFiles -Id 'WAZ-005' -Title 'Wazuh collects the Security event channel' `
        -Pattern '<location>\s*Security\s*</location>' -Files $WazFiles
    Test-PatternInFiles -Id 'WAZ-006' -Title 'Wazuh collects the Sysmon event channel' `
        -Pattern 'Microsoft-Windows-Sysmon/Operational' -Files $WazFiles
    Test-PatternInFiles -Id 'WAZ-007' -Title 'Wazuh collects the PowerShell event channel' `
        -Pattern 'Microsoft-Windows-PowerShell/Operational' -Files $WazFiles
}

# ============================== 3) SYSMON ===================================
Write-Section "3) Sysmon"

# Ten service khac nhau theo ban cai (Sysmon64 tren x64, Sysmon tren x86)
$SysmonSvcName = $null
foreach ($n in @('Sysmon64', 'Sysmon')) {
    if (Get-SvcCim $n) { $SysmonSvcName = $n; break }
}

if (-not $SysmonSvcName) {
    Add-Result -Status FAIL -Id 'SYS-001' -Title 'Sysmon service is installed'          -Detail 'neither Sysmon64 nor Sysmon service found'
    Add-Result -Status SKIP -Id 'SYS-002' -Title 'Sysmon service start type is Automatic' -Detail 'Sysmon not installed'
    Add-Result -Status SKIP -Id 'SYS-003' -Title 'Sysmon service is running'            -Detail 'Sysmon not installed'
} else {
    Test-SvcAspect -Id 'SYS-001' -Title 'Sysmon service is installed'            -ServiceName $SysmonSvcName -Aspect Installed
    Test-SvcAspect -Id 'SYS-002' -Title 'Sysmon service start type is Automatic' -ServiceName $SysmonSvcName -Aspect Automatic
    Test-SvcAspect -Id 'SYS-003' -Title 'Sysmon service is running'              -ServiceName $SysmonSvcName -Aspect Running
}

# Driver SysmonDrv la thanh phan thu thap su kien thuc su
$drv = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue
if (-not $drv) {
    Add-Result -Status FAIL -Id 'SYS-004' -Title 'Sysmon driver (SysmonDrv) is running' -Detail 'SysmonDrv driver not found'
} elseif ($drv.State -eq 'Running') {
    Add-Result -Status PASS -Id 'SYS-004' -Title 'Sysmon driver (SysmonDrv) is running' -Detail ("State={0}" -f $drv.State)
} else {
    Add-Result -Status FAIL -Id 'SYS-004' -Title 'Sysmon driver (SysmonDrv) is running' -Detail ("State={0}, expected Running" -f $drv.State)
}

# Tim file thuc thi Sysmon de doc cau hinh DANG CHAY bang "-c"
function Get-SysmonExe {
    foreach ($n in @('Sysmon64', 'Sysmon')) {
        $cim = Get-SvcCim $n
        if ($cim -and $cim.PathName) {
            $p = $cim.PathName.Trim('"')
            if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
        }
    }
    foreach ($p in @("$env:SystemRoot\Sysmon64.exe", "$env:SystemRoot\Sysmon.exe",
                     "$env:SystemRoot\System32\Sysmon64.exe", "$env:SystemRoot\System32\Sysmon.exe")) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
    $cmd = Get-Command -Name 'Sysmon64.exe' -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command -Name 'Sysmon.exe' -ErrorAction SilentlyContinue }
    if ($cmd) { return $cmd.Source }
    return $null
}

$SysmonExe         = Get-SysmonExe
$SysmonConfigLines = @()
$SysmonConfigOk    = $false
if ($SysmonExe) {
    $raw = Get-NativeOutput -Exe $SysmonExe -Arguments @('-c')
    if ($raw) {
        $SysmonConfigLines = $raw -split "`r?`n"
        if ($raw -match 'Rule configuration') { $SysmonConfigOk = $true }
    }
}

# Tra ve @{Mode; Count; Raw} cho 1 nhom rule trong output "sysmon -c", $null neu khong co.
#
# LUU Y dinh dang: dong mo dau nhom rule co hau to khac nhau theo phien ban Sysmon:
#   Sysmon cu :   - ProcessCreate     onmatch: exclude
#   Sysmon moi:   - ProcessCreate     onmatch: exclude combine rules using [Or]
# Vi vay mode phai lay bang token ngay SAU "onmatch:", khong duoc lay tu cuoi dong
# (lay tu cuoi dong se ra [Or]/[And] tren ban moi).
function Get-SysmonRuleBlock {
    # $Lines KHONG duoc dat Mandatory: output that cua "sysmon -c" co dong trong,
    # va PowerShell 5.1 tu choi bind [string[]] Mandatory neu mang co phan tu rong.
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()]
        [string[]]$Lines,
        [Parameter(Mandatory)][string]$EventName
    )

    if (-not $Lines) { return $null }

    $inBlock = $false; $mode = ''; $count = 0; $raw = ''
    foreach ($line in $Lines) {
        if (($line -match '^\s*-\s+[A-Za-z]') -and ($line -match 'onmatch:')) {
            if ($inBlock) { break }
            $name = ''
            if ($line -match '^\s*-\s+([A-Za-z0-9_]+)') { $name = $Matches[1] }
            if ($name -eq $EventName) {
                $inBlock = $true; $count = 0; $raw = $line.Trim()
                if ($line -match 'onmatch:\s*([A-Za-z]+)') { $mode = $Matches[1].ToLower() }
            }
            continue
        }
        if ($inBlock) {
            if ($line -match '^\s*-\s') { break }
            if ($line.Trim().Length -gt 0) { $count++ }
        }
    }
    if (-not $inBlock) { return $null }
    return [pscustomobject]@{ Mode = $mode; Count = $count; Raw = $raw }
}

function Test-SysmonEvent {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][string]$EventName
    )
    $title = "Sysmon logs Event ID $EventId ($EventName)"

    if (-not $SysmonExe) {
        Add-Result -Status SKIP -Id $Id -Title $title -Detail 'Sysmon executable not found'
        return
    }
    if (-not $SysmonConfigOk) {
        Add-Result -Status FAIL -Id $Id -Title $title -Detail "'sysmon -c' returned no rule configuration"
        return
    }

    $blk = Get-SysmonRuleBlock -Lines $SysmonConfigLines -EventName $EventName
    if (-not $blk) {
        Add-Result -Status FAIL -Id $Id -Title $title -Detail ("running config has no '{0}' rule group" -f $EventName)
        return
    }

    if ($blk.Mode -eq 'exclude') {
        Add-Result -Status PASS -Id $Id -Title $title `
            -Detail ("onmatch=exclude ({0} exclusion condition(s)) -> logged by default" -f $blk.Count)
    } elseif ($blk.Mode -eq 'include') {
        if ($blk.Count -gt 0) {
            Add-Result -Status WARN -Id $Id -Title $title `
                -Detail ("onmatch=include ({0} condition(s)) -> ONLY matching events are logged" -f $blk.Count)
        } else {
            Add-Result -Status FAIL -Id $Id -Title $title `
                -Detail 'onmatch=include with NO conditions -> event is fully suppressed'
        }
    } else {
        Add-Result -Status WARN -Id $Id -Title $title `
            -Detail ("could not parse onmatch value from line: {0}" -f $blk.Raw)
    }
}

Test-SysmonEvent -Id 'SYS-005' -EventId 1  -EventName 'ProcessCreate'
Test-SysmonEvent -Id 'SYS-006' -EventId 3  -EventName 'NetworkConnect'
Test-SysmonEvent -Id 'SYS-007' -EventId 5  -EventName 'ProcessTerminate'
Test-SysmonEvent -Id 'SYS-008' -EventId 11 -EventName 'FileCreate'
Test-SysmonEvent -Id 'SYS-009' -EventId 23 -EventName 'FileDelete'
# Event 4 (Sysmon service state) va 16 (config change) luon duoc phat sinh,
# khong phu thuoc cau hinh -> khong kiem tra.

# Bang chung thuc te: kenh log Sysmon ton tai, dang bat va co su kien
$sysmonLog = $null
try { $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop } catch { $sysmonLog = $null }
$t = 'Sysmon event channel is enabled and has records'
if (-not $sysmonLog) {
    Add-Result -Status FAIL -Id 'SYS-010' -Title $t -Detail 'Microsoft-Windows-Sysmon/Operational channel not found'
} elseif (-not $sysmonLog.IsEnabled) {
    Add-Result -Status FAIL -Id 'SYS-010' -Title $t -Detail 'channel exists but is disabled'
} elseif ($sysmonLog.RecordCount -le 0) {
    Add-Result -Status FAIL -Id 'SYS-010' -Title $t -Detail 'channel is enabled but contains no records'
} else {
    Add-Result -Status PASS -Id 'SYS-010' -Title $t -Detail ("{0} record(s)" -f $sysmonLog.RecordCount)
}

# ===================== 4) COMMAND LOGGING (tuong duong cmdlog) ==============
Write-Section "4) Command logging (Windows equivalent of cmdlog)"

# Audit Process Creation.
# Dung GUID subcategory de khong phu thuoc ngon ngu OS, va doc ket qua qua "/r"
# (CSV) thay vi dang text: cot "Setting" dang text BI DICH theo ngon ngu Windows,
# con cot cuoi cua CSV la "Setting Value" dang SO nen doc duoc tren moi locale:
#   0 = No auditing | 1 = Success | 2 = Failure | 3 = Success and Failure
$procCreateGuid = '{0CCE922B-69AE-11D9-BED3-505054503030}'
$apOut = Get-NativeOutput -Exe 'auditpol.exe' -Arguments @('/get', "/subcategory:$procCreateGuid", '/r')

$apValue = $null
if ($apOut) {
    foreach ($line in ($apOut -split "`r?`n")) {
        if ($line -match '0cce922b-69ae-11d9-bed3-505054503030') {
            $cols = $line.Split(',')
            $last = $cols[$cols.Count - 1].Trim()
            if ($last -match '^\d+$') { $apValue = [int]$last }
        }
    }
}

$t = 'Audit policy logs process creation (Event ID 4688)'
if ($null -eq $apValue) {
    Add-Result -Status WARN -Id 'CMD-001' -Title $t -Detail 'could not read the auditpol setting value'
} elseif ($apValue -eq 1 -or $apValue -eq 3) {
    Add-Result -Status PASS -Id 'CMD-001' -Title $t -Detail ("auditpol setting value={0} (success auditing on)" -f $apValue)
} elseif ($apValue -eq 2) {
    Add-Result -Status FAIL -Id 'CMD-001' -Title $t -Detail 'auditpol setting value=2 (failure only, success events not logged)'
} else {
    Add-Result -Status FAIL -Id 'CMD-001' -Title $t -Detail ("auditpol setting value={0} (no auditing)" -f $apValue)
}

Test-RegValueIs -Id 'CMD-002' -Title 'Process creation events include the command line' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name 'ProcessCreationIncludeCmdLine_Enabled' -Expected 1

Test-RegValueIs -Id 'CMD-003' -Title 'PowerShell script block logging is enabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockLogging' -Expected 1

Test-RegValueIs -Id 'CMD-004' -Title 'PowerShell module logging is enabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
    -Name 'EnableModuleLogging' -Expected 1

# ---------------- tong ket ----------------
Write-ReportLine
Write-ReportLine -Text '======================================================================'
Write-ReportLine -Text ' SUMMARY'
Write-ReportLine -Text '======================================================================'
Write-ReportLine -Text (' PASS (compliant)     : {0}' -f $script:CntPass) -Color 'Green'
Write-ReportLine -Text (' WARN (partial)       : {0}' -f $script:CntWarn) -Color 'Yellow'
Write-ReportLine -Text (' FAIL (non-compliant) : {0}' -f $script:CntFail) -Color 'Red'
Write-ReportLine -Text (' SKIP (not applicable): {0}' -f $script:CntSkip) -Color 'DarkGray'
Write-ReportLine
if ($script:CntFail -gt 0) {
    Write-ReportLine -Text (' VERDICT: BASELINE NOT MET ({0} failed check(s))' -f $script:CntFail) -Color 'Red'
    Write-ReportLine -Text ' Failed checks:'
    foreach ($l in $script:FailedList) { Write-ReportLine -Text ("   - " + $l) -Color 'Red' }
} else {
    Write-ReportLine -Text ' VERDICT: BASELINE MET (no failed checks)' -Color 'Green'
}

Write-Host ""
Write-Host "==> Check results written to: $ReportPath" -ForegroundColor Green
Write-Host ""

# ==================================================================
# 9. [3] REMEDIATE - ap baseline bang LGPO (thay doi cau hinh he thong)
# ==================================================================
$doRemediate = $false
if ($Recheck) {
    # Recheck chi de XAC NHAN hien trang sau khi da sua thu cong. Neu ap baseline
    # o day thi post_<BASE>.PolicyRules vua chup o buoc [1] khong con phan anh
    # dung hien trang nguoi lam audit vua sua.
    Write-Host "==> Recheck mode: the baseline is not applied." -ForegroundColor DarkGray
} else {
    Write-Host "======================================================================"
    Write-Host " [3] REMEDIATE - this will APPLY the selected baseline to this machine"
    Write-Host ("     baseline: {0}" -f $Chosen.Name)
    Write-Host "     Local Group Policy will be CHANGED. Logs -> lgpo.out / lgpo.err"
    Write-Host "======================================================================"
    $ans = (Read-Host "Run remediation now? [y/N]").Trim()
    if ($ans -match '^[Yy]$') {
        $doRemediate = $true
    } else {
        Write-Host "==> Skipping remediation." -ForegroundColor DarkGray
    }
}

if ($doRemediate) {
    Write-Host ""
    Write-Host "==> Applying baseline..." -ForegroundColor Cyan
    $LgpoOut = Join-Path $AuditDir 'lgpo.out'
    $LgpoErr = Join-Path $AuditDir 'lgpo.err'
    $applyCode = Invoke-Native -Exe $LgpoExe -Arguments @('/p', $Chosen.FullName, '/v') `
                    -StdoutFile $LgpoOut -StderrFile $LgpoErr -Step 'APPLY'
    if ($applyCode -ne 0) {
        Write-Host "[WARNING] LGPO reported an error while applying (see lgpo.err)." -ForegroundColor Yellow
    }

    # lam moi policy de co hieu luc (khong ghi log file)
    Invoke-Native -Exe 'gpupdate.exe' -Arguments @('/force') -Step 'GPUPDATE' | Out-Null
    Write-Host ""
    Write-Host "==> Baseline applied. Re-run this script with -Recheck to produce" -ForegroundColor Green
    Write-Host "    post_$Tag.PolicyRules and post_scriptcheck_$Tag.txt." -ForegroundColor Green
}

# ============================================================
# 10. Ket thuc
# ============================================================
Write-Host ""
Write-Host "======================================================================"
Write-Host " DONE"
Write-Host "======================================================================"
Get-ChildItem -LiteralPath $AuditDir -File | Sort-Object Name | ForEach-Object {
    Write-Host ("  " + $_.Name)
}
Write-Host "  -> result folder: $AuditDir"
Write-Host "Compare before/after: open Policy Analyzer -> Add the 2 .PolicyRules files -> View/Compare."
Write-Host "======================================================================"
