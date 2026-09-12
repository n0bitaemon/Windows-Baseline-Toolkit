#Requires -Version 5.1
<#
    Apply-Baseline.ps1
    ------------------
    Ap dung baseline (.PolicyRules) bang LGPO.exe va chup cau hinh GPO
    truoc / sau khi ap ra file .PolicyRules.

    Cau truc thu muc mong doi (dat script ngang hang voi cac thu muc nay):
        .\LGPO\LGPO.exe
        .\PolicyAnalyzer\GPO2PolicyRules.exe
        .\policy_rules\*.PolicyRules
        .\Apply-Baseline.ps1

    Ket qua trong audit_<hostname>_<ip>_<timestamp>_<manv>\  (dung 4 file):
        pre_<tag>.PolicyRules   - policy hien tai TRUOC khi ap
        post_<tag>.PolicyRules  - policy SAU khi ap
        lgpo.out                - stdout cua "lgpo /p": cac setting da ap thanh cong
        lgpo.err                - stderr cua "lgpo /p": loi trong qua trinh ap

    Yeu cau: chay bang quyen Administrator.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ============================================================
# 0. Cau hinh duong dan (theo $PSScriptRoot)
# ============================================================
$ScriptRoot     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LgpoExe        = Join-Path $ScriptRoot 'LGPO\LGPO.exe'
$Gpo2RulesExe   = Join-Path $ScriptRoot 'PolicyAnalyzer\GPO2PolicyRules.exe'
$PolicyRulesDir = Join-Path $ScriptRoot 'policy_rules'

# ============================================================
# 1. Kiem tra dieu kien tien quyet
# ============================================================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "[LOI] Script phai duoc chay bang quyen Administrator." -ForegroundColor Red
    exit 1
}

foreach ($tool in @(@{P=$LgpoExe;N='LGPO.exe'}, @{P=$Gpo2RulesExe;N='GPO2PolicyRules.exe'})) {
    if (-not (Test-Path $tool.P)) {
        Write-Host "[LOI] Khong tim thay $($tool.N) tai: $($tool.P)" -ForegroundColor Red
        if ($tool.N -eq 'GPO2PolicyRules.exe') {
            Write-Host "      GPO2PolicyRules.exe nam trong ban tai Policy Analyzer (canh PolicyAnalyzer.exe)." -ForegroundColor Red
        }
        exit 1
    }
}

if (-not (Test-Path $PolicyRulesDir)) {
    Write-Host "[LOI] Khong tim thay thu muc policy_rules tai: $PolicyRulesDir" -ForegroundColor Red
    exit 1
}

# ============================================================
# 2. Nhap thong tin dinh danh
# ============================================================
function Read-NonEmpty([string]$Prompt) {
    do {
        $v = (Read-Host $Prompt).Trim()
        if ([string]::IsNullOrWhiteSpace($v)) {
            Write-Host "    Gia tri khong duoc de trong. Nhap lai." -ForegroundColor Yellow
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
            Write-Host "    IP khong hop le. Vi du: 10.20.30.40. Nhap lai." -ForegroundColor Yellow
        }
    } until ($ok)
    return $v
}

Write-Host "==== THU THAP THONG TIN AUDIT ====" -ForegroundColor Cyan
$EmpCode  = Read-NonEmpty  "Nhap ma nhan vien"
$DeviceIp = Read-IPAddress "Nhap IP address cua thiet bi"

$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Hostname  = $env:COMPUTERNAME

# ============================================================
# 3. Tao tag va thu muc audit
# ============================================================
function Format-Token([string]$s) {
    return ($s -replace '[\\/:*?"<>|\s]', '-')
}

$Tag = '{0}_{1}_{2}_{3}' -f (Format-Token $Hostname), (Format-Token $DeviceIp), $Timestamp, (Format-Token $EmpCode)

$AuditDir = Join-Path $ScriptRoot ("audit_" + $Tag)
New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null

Write-Host ""
Write-Host "Hostname    : $Hostname"
Write-Host "IP          : $DeviceIp"
Write-Host "Ma nhan vien: $EmpCode"
Write-Host "Timestamp   : $Timestamp"
Write-Host "Thu muc audit: $AuditDir"
Write-Host ""

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
        Write-Host "[$Step] Khong chay duoc $Exe : $($_.Exception.Message)" -ForegroundColor Red
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
        Write-Host "  -> Da tao: $OutFile" -ForegroundColor Green
    } else {
        Write-Host "  -> [CANH BAO] Khong tao duoc $OutFile" -ForegroundColor Yellow
    }
    return $code
}

# ============================================================
# 4a. Snapshot TRUOC khi ap dung
# ============================================================
Write-Host "==== CHUP CAU HINH GPO TRUOC KHI AP DUNG ====" -ForegroundColor Cyan
$PreFile = Join-Path $AuditDir ("pre_" + $Tag + ".PolicyRules")
New-PolicyRulesSnapshot -OutFile $PreFile -DisplayName ("pre_" + $Tag) -Step 'PRE' | Out-Null
Write-Host ""

# ============================================================
# 5. Liet ke va chon file .PolicyRules
# ============================================================
$Rules = @(Get-ChildItem -Path $PolicyRulesDir -Filter '*.PolicyRules' -File | Sort-Object Name)
if ($Rules.Count -eq 0) {
    Write-Host "[LOI] Khong co file .PolicyRules nao trong: $PolicyRulesDir" -ForegroundColor Red
    exit 1
}

Write-Host "==== CHON BASELINE DE AP DUNG ====" -ForegroundColor Cyan
for ($i = 0; $i -lt $Rules.Count; $i++) {
    Write-Host ("  [{0}] {1}" -f ($i + 1), $Rules[$i].Name)
}

do {
    $sel = (Read-Host "Nhap so thu tu baseline can ap dung (1-$($Rules.Count))").Trim()
    $valid = ($sel -match '^\d+$') -and ([int]$sel -ge 1) -and ([int]$sel -le $Rules.Count)
    if (-not $valid) {
        Write-Host "    Lua chon khong hop le. Nhap lai." -ForegroundColor Yellow
    }
} until ($valid)

$Chosen = $Rules[[int]$sel - 1]
Write-Host "Da chon: $($Chosen.Name)" -ForegroundColor Green
Write-Host ""

# ============================================================
# 6. Ap dung baseline (LGPO /p) -> lgpo.out / lgpo.err
# ============================================================
Write-Host "==== AP DUNG BASELINE ====" -ForegroundColor Cyan
$LgpoOut = Join-Path $AuditDir 'lgpo.out'
$LgpoErr = Join-Path $AuditDir 'lgpo.err'
$applyCode = Invoke-Native -Exe $LgpoExe -Arguments @('/p', $Chosen.FullName, '/v') `
                -StdoutFile $LgpoOut -StderrFile $LgpoErr -Step 'APPLY'
if ($applyCode -ne 0) {
    Write-Host "[CANH BAO] LGPO bao loi khi ap dung (xem lgpo.err). Van tiep tuc chup snapshot sau." -ForegroundColor Yellow
}

# lam moi policy de co hieu luc (khong ghi log file)
Invoke-Native -Exe 'gpupdate.exe' -Arguments @('/force') -Step 'GPUPDATE' | Out-Null
Write-Host ""

# ============================================================
# 4b. Snapshot SAU khi ap dung
# ============================================================
Write-Host "==== CHUP CAU HINH GPO SAU KHI AP DUNG ====" -ForegroundColor Cyan
$PostFile = Join-Path $AuditDir ("post_" + $Tag + ".PolicyRules")
New-PolicyRulesSnapshot -OutFile $PostFile -DisplayName ("post_" + $Tag) -Step 'POST' | Out-Null
Write-Host ""

# ============================================================
# 7. Ket thuc
# ============================================================
Write-Host "==== HOAN TAT ====" -ForegroundColor Cyan
Write-Host "Ket qua trong: $AuditDir" -ForegroundColor Green
Write-Host ("  - {0}" -f [IO.Path]::GetFileName($PreFile))
Write-Host ("  - {0}" -f [IO.Path]::GetFileName($PostFile))
Write-Host "  - lgpo.out  (cac setting da ap thanh cong)"
Write-Host "  - lgpo.err  (loi khi ap, neu co)"
Write-Host "So sanh truoc/sau: mo Policy Analyzer -> Add 2 file .PolicyRules -> View/Compare." -ForegroundColor Green