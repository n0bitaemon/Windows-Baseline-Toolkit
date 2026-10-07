#Requires -Version 5.1
<#
    ApplyBaselinev2.ps1
    -------------------
    Phien ban 2 cua Apply-Baseline.ps1. KHONG can file .PolicyRules dung san cho
    tung role: script tu doc goi Microsoft Security Baseline trong .\baseline_template\,
    tu suy ra cac mode ma goi ho tro, cho nguoi audit chon, roi:
      - sinh baseline tham chieu (.PolicyRules) = GPO cua mode + cac file delta
      - ap baseline GIONG HET Baseline-LocalInstall.ps1 cua Microsoft (LGPO /g tung GPO)
        roi ap tiep cac file delta (LGPO /t /s /a) theo thu tu lop.

    Cau truc thu muc mong doi (dat script ngang hang voi cac thu muc nay):
        .\LGPO\LGPO.exe
        .\PolicyAnalyzer\GPO2PolicyRules.exe
        .\baseline_template\<goi baseline cua Microsoft>\GPOs\{GUID}\...
        .\deltas\...                      (tuy chon, xem ben duoi)
        .\ApplyBaselinev2.ps1

    MODE - tu suy ra tu ten GPO trong goi (quy uoc dat ten cua Microsoft):
        client-domain      Client, domain-joined          : tat ca GPO client + GPO dung chung
        client-nondomain   Client, non-domain-joined      : nhu tren + DeltaForNonDomainJoined
        server-member      Server, member server          : bo GPO co ten chua "Domain Controller"
        server-nondomain   Server, non-domain-joined      : nhu tren + DeltaForNonDomainJoined
        server-dc          Server, domain controller      : bo GPO co ten chua "Member Server"
    Goi dat ten khac thuong -> them file baseline.psd1 vao thu muc goi de khai bao tay:
        @{ Modes = @{ 'server-member' = @('MSFT ... - Member Server', ...); ... } }

    DELTA - cac thay doi rieng cua to chuc so voi baseline, ap SAU GPO cua Microsoft
    (ghi sau thang). Thu tu ap (file trong moi thu muc ap theo thu tu ten):
        1. <goi>\Scripts\ConfigFiles\DeltaForNonDomainJoined.inf/.txt  (chi mode *-nondomain)
        2. deltas\common\
        3. deltas\<mode>\
        4. deltas\<ten thu muc goi baseline>\common\
        5. deltas\<ten thu muc goi baseline>\<mode>\
    Dinh dang file delta theo phan mo rong:
        *.txt  LGPO text (registry policy)   -> LGPO /t   (ho tro DELETE, CLEAR, ...)
        *.inf  security template            -> LGPO /s   (URA, password policy, security options)
        *.csv  advanced audit (audit.csv)   -> LGPO /a
    File co phan mo rong khac (.md, .example, ...) bi bo qua.

    Audit khong xong trong 1 lan chay: lan dau lay hien trang, sau do nguoi lam
    audit sua cau hinh thu cong (onboard MDE, cai Wazuh/Sysmon, bat command
    logging...), roi chay lai voi -Recheck de xac nhan. Vi vay co 2 che do:

      LAN DAU (khong co -Recheck) - chon goi + mode, tao folder audit_<BASE>\ moi:
        [0] REFERENCE: baseline tham chieu       -> baseline_<BASE>.PolicyRules
                       bao cao tung muc delta    -> delta_report_<BASE>.txt
        [1] SNAPSHOT : chup policy hien tai      -> pre_<BASE>.PolicyRules
        [2] CHECK    : script check security stack -> pre_scriptcheck_<BASE>.txt
        [3] REMEDIATE: LGPO /g + delta (co xac nhan y/N) -> lgpo.out + lgpo.err
                       KHONG chup post_<BASE>.PolicyRules o buoc nay.
                       Khong chay tren domain controller (giong script cua Microsoft).

      RECHECK (-Recheck) - chon 1 folder audit_* co san, dung lai <BASE> cu:
        [1] SNAPSHOT : chup policy hien tai -> post_<BASE>.PolicyRules
        [2] CHECK    : script check security stack -> post_scriptcheck_<BASE>.txt
        Khong chay REMEDIATE. File cu bi GHI DE.

    So sanh: mo Policy Analyzer -> Add baseline_*, pre_*, post_* -> View/Compare.

    Tham so:
        -Recheck (hoac --recheck)  chon folder audit_* co san, gen lai bo file post_*
        -List    (hoac --list)     chi liet ke goi / mode / GPO / delta, khong thay doi gi
        -Baseline <ten thu muc>    chon goi baseline, bo qua menu
        -Mode <mode>               chon mode, bo qua menu
        -Exclude <tu khoa,...>     bo cac GPO co ten chua tu khoa (vd 'Credential Guard','BitLocker')

    Yeu cau: chay bang quyen Administrator (tru -List).
#>

[CmdletBinding()]
param(
    [switch]$Recheck,
    [switch]$List,
    [string]$Baseline,
    [ValidateSet('client-domain', 'client-nondomain', 'server-member', 'server-nondomain', 'server-dc')]
    [string]$Mode,
    [string[]]$Exclude,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = 'Stop'

# ============================================================
# 0. Doc tham so kieu Linux (--recheck, --list) cho dong bo voi audit.sh
# ============================================================
if ($ExtraArgs) {
    foreach ($a in $ExtraArgs) {
        switch -Regex ($a) {
            '^--recheck$' { $Recheck = $true }
            '^--list$'    { $List = $true }
            '^(--help|-h)$' {
                Write-Host "Usage: .\ApplyBaselinev2.ps1 [-Recheck | --recheck] [-List | --list]"
                Write-Host "                             [-Baseline <folder>] [-Mode <mode>] [-Exclude <kw>,<kw>]"
                Write-Host ""
                Write-Host "  (no flag)   First run: pick a baseline package + mode, create a new audit_<BASE>\"
                Write-Host "              folder, produce baseline_<BASE>.PolicyRules, delta_report_<BASE>.txt,"
                Write-Host "              pre_<BASE>.PolicyRules and pre_scriptcheck_<BASE>.txt, then optionally"
                Write-Host "              apply the baseline + deltas (lgpo.out / lgpo.err)."
                Write-Host "  -Recheck    Pick an existing audit_* folder and re-verify the machine."
                Write-Host "              Regenerates post_<BASE>.PolicyRules and post_scriptcheck_<BASE>.txt,"
                Write-Host "              OVERWRITING them if present. The baseline is not applied."
                Write-Host "  -List       Show detected baseline packages, modes, GPOs and delta files. No changes."
                Write-Host "  -Baseline   Baseline package folder name under baseline_template\ (skips the menu)."
                Write-Host "  -Mode       client-domain | client-nondomain | server-member | server-nondomain | server-dc"
                Write-Host "  -Exclude    Skip GPOs whose name contains any of the keywords."
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
$ScriptRoot   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LgpoExe      = Join-Path $ScriptRoot 'LGPO\LGPO.exe'
$Gpo2RulesExe = Join-Path $ScriptRoot 'PolicyAnalyzer\GPO2PolicyRules.exe'
$BaselineRoot = Join-Path $ScriptRoot 'baseline_template'
$DeltaRoot    = Join-Path $ScriptRoot 'deltas'

$ModeKeys = @('client-domain', 'client-nondomain', 'server-member', 'server-nondomain', 'server-dc')
$ModeLabels = @{
    'client-domain'    = 'Client - domain-joined'
    'client-nondomain' = 'Client - non-domain-joined (standalone / workgroup)'
    'server-member'    = 'Server - domain-joined member server'
    'server-nondomain' = 'Server - non-domain-joined (standalone / workgroup)'
    'server-dc'        = 'Server - domain controller'
}
$DeltaExtensions = @('.txt', '.inf', '.csv')

# ============================================================
# 2. Ham dung chung
# ============================================================
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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

function Read-YesNo([string]$Prompt) {
    $ans = (Read-Host "$Prompt [y/N]").Trim()
    return ($ans -match '^[Yy]$')
}

# Tra ve INDEX (0-based) cua muc duoc chon. -Default la so thu tu (1-based) goi y,
# nguoi dung chi can Enter de chon.
function Select-FromList {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Items,
        [int]$Default = 0
    )
    Write-Host $Title -ForegroundColor Cyan
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $mark = if (($i + 1) -eq $Default) { '   <- suggested' } else { '' }
        Write-Host ("  [{0}] {1}{2}" -f ($i + 1), $Items[$i], $mark)
    }
    if ($Default -ge 1) {
        $prompt = "Select a number [1-{0}] (Enter = {1})" -f $Items.Count, $Default
    } else {
        $prompt = "Select a number [1-{0}]" -f $Items.Count
    }
    do {
        $sel = (Read-Host $prompt).Trim()
        if ($sel -eq '' -and $Default -ge 1) { $sel = "$Default" }
        $valid = ($sel -match '^\d+$') -and ([int]$sel -ge 1) -and ([int]$sel -le $Items.Count)
        if (-not $valid) { Write-Host "    Invalid choice, please try again." -ForegroundColor Yellow }
    } until ($valid)
    return ([int]$sel - 1)
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
# 3. Phat hien goi baseline va mode
# ============================================================

# Ten GPO doc tu Backup.xml (fallback bkupInfo.xml)
function Get-GpoDisplayName([string]$GpoDir) {
    $backup = Join-Path $GpoDir 'Backup.xml'
    if (Test-Path -LiteralPath $backup) {
        try {
            $x = [xml](Get-Content -LiteralPath $backup -Raw -Encoding UTF8)
            $n = $x.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
            if ($n) { return $n.Trim() }
        } catch {}
    }
    $info = Join-Path $GpoDir 'bkupInfo.xml'
    if (Test-Path -LiteralPath $info) {
        try {
            $x = [xml](Get-Content -LiteralPath $info -Raw -Encoding UTF8)
            $n = $x.BackupInst.GPODisplayName.InnerText
            if ($n) { return $n.Trim() }
        } catch {}
    }
    return $null
}

# Phan loai 1 GPO theo ten:
#   Server : ten chua "Member Server" / "Domain Controller", hoac chi nhac toi Server
#   Client : chi nhac toi Windows 10/11
#   Shared : khong nhac toi OS nao (IE11) hoac nhac ca hai ("Windows 10 ... and Server ...")
function Get-GpoScope([string]$Name) {
    if ($Name -match 'Member Server|Domain Controller') { return 'Server' }
    $isServer = $Name -match '\bServer\b'
    $isClient = $Name -match '\bWindows 1\d\b'
    if ($isServer -and -not $isClient) { return 'Server' }
    if ($isClient -and -not $isServer) { return 'Client' }
    return 'Shared'
}

# Tat ca GPO backup trong 1 goi (quet de quy, bo trung theo GUID)
function Get-BaselineGpos([string]$Dir) {
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    $files = @(Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter 'backup.xml' -ErrorAction SilentlyContinue |
               Sort-Object FullName)
    foreach ($f in $files) {
        $g = $f.Directory
        if ($g.Name -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { continue }
        $k = $g.Name.ToUpperInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $name = Get-GpoDisplayName $g.FullName
        if (-not $name) { $name = $g.Name }
        $out.Add([pscustomobject]@{ Name = $name; Guid = $g.Name; Path = $g.FullName; Scope = (Get-GpoScope $name) })
    }
    return @($out | Sort-Object Name)
}

# Suy ra mode tu ten GPO - cho ra dung danh sach GPO nhu Baseline-LocalInstall.ps1
function Get-AutoModes($Gpos) {
    $modes  = [ordered]@{}
    $client = @($Gpos | Where-Object { $_.Scope -eq 'Client' })
    $server = @($Gpos | Where-Object { $_.Scope -eq 'Server' })
    $shared = @($Gpos | Where-Object { $_.Scope -eq 'Shared' })

    if ($client.Count -gt 0) {
        $set = @(($client + $shared) | Sort-Object Name)
        $modes['client-domain']    = $set
        $modes['client-nondomain'] = $set
    }
    if ($server.Count -gt 0) {
        if (@($server | Where-Object { $_.Name -match 'Member Server' }).Count -gt 0) {
            $set = @((@($server | Where-Object { $_.Name -notmatch 'Domain Controller' }) + $shared) | Sort-Object Name)
            $modes['server-member']    = $set
            $modes['server-nondomain'] = $set
        }
        if (@($server | Where-Object { $_.Name -match 'Domain Controller' }).Count -gt 0) {
            $modes['server-dc'] = @((@($server | Where-Object { $_.Name -notmatch 'Member Server' }) + $shared) | Sort-Object Name)
        }
    }
    return $modes
}

# Mode khai bao tay trong baseline.psd1 (cho goi dat ten khac thuong)
function Get-OverrideModes($Gpos, [string]$File) {
    $data = Import-PowerShellDataFile -LiteralPath $File
    if (-not $data.ContainsKey('Modes')) { throw "$File : missing 'Modes' table" }
    foreach ($k in $data.Modes.Keys) {
        if ($ModeKeys -notcontains $k) { throw ("{0} : unknown mode '{1}' (valid: {2})" -f $File, $k, ($ModeKeys -join ', ')) }
    }
    $modes = [ordered]@{}
    foreach ($m in $ModeKeys) {
        if (-not $data.Modes.ContainsKey($m)) { continue }
        $set = @()
        foreach ($n in @($data.Modes[$m])) {
            $g = $Gpos | Where-Object { $_.Name -eq $n } | Select-Object -First 1
            if (-not $g) { throw ("{0} : GPO '{1}' (mode {2}) not found in this package" -f $File, $n, $m) }
            $set += $g
        }
        $modes[$m] = @($set | Sort-Object Name)
    }
    return $modes
}

function Get-Baselines {
    $result = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $BaselineRoot -PathType Container)) { return @() }
    foreach ($d in @(Get-ChildItem -LiteralPath $BaselineRoot -Directory | Sort-Object Name)) {
        $gpos = @(Get-BaselineGpos $d.FullName)
        if ($gpos.Count -eq 0) { continue }
        $override = Join-Path $d.FullName 'baseline.psd1'
        $src = 'auto-detected'
        $err = $null
        $modes = [ordered]@{}
        try {
            if (Test-Path -LiteralPath $override -PathType Leaf) {
                $modes = Get-OverrideModes $gpos $override
                $src = 'baseline.psd1'
            } else {
                $modes = Get-AutoModes $gpos
            }
            if ($modes.Count -eq 0) { $err = 'no mode could be derived from the GPO names - add a baseline.psd1' }
        } catch {
            $err = $_.Exception.Message
        }
        $result.Add([pscustomobject]@{
            Name = $d.Name; Path = $d.FullName; Gpos = $gpos; Modes = $modes; Source = $src; Error = $err
        })
    }
    return $result.ToArray()
}

# Thong tin may: OS + DomainRole -> goi y mode
function Get-MachineInfo {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $dv = $null
    try {
        $dv = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction Stop).DisplayVersion
    } catch { $dv = $null }

    $caption = if ($os) { [string]$os.Caption } else { '' }
    $family = $null; $full = $null
    if ($caption -match 'Windows Server (\d{4})') {
        $family = "Windows Server $($Matches[1])"; $full = $family
    } elseif ($caption -match 'Windows (1\d)') {
        $family = "Windows $($Matches[1])"
        $full = if ($dv) { "$family $dv" } else { $family }
    }

    $role = if ($cs) { [int]$cs.DomainRole } else { -1 }
    $roleText = switch ($role) {
        0 { 'standalone workstation' } 1 { 'member workstation' } 2 { 'standalone server' }
        3 { 'member server' } 4 { 'backup domain controller' } 5 { 'primary domain controller' }
        default { 'unknown' }
    }
    $suggest = switch ($role) {
        0 { 'client-nondomain' } 1 { 'client-domain' } 2 { 'server-nondomain' }
        3 { 'server-member' } 4 { 'server-dc' } 5 { 'server-dc' }
        default { $null }
    }
    return [pscustomobject]@{
        Caption       = $caption
        Family        = $family
        Full          = $full
        DomainRole    = $role
        RoleText      = $roleText
        SuggestedMode = $suggest
        IsServer      = ($os -and $os.ProductType -ne 1)
        IsDC          = ($role -ge 4)
    }
}

# 2 = goi dung OS + phien ban, 1 = dung ho OS, 0 = khong khop
function Get-OsMatchScore($Bl, $Machine) {
    if (-not $Machine.Family) { return 0 }
    $names = @($Bl.Gpos | ForEach-Object { $_.Name })
    if ($Machine.Full -and @($names | Where-Object { $_ -like "*$($Machine.Full)*" }).Count -gt 0) { return 2 }
    if (@($names | Where-Object { $_ -like "*$($Machine.Family)*" }).Count -gt 0) { return 1 }
    return 0
}

# ============================================================
# 4. File delta
# ============================================================
function New-DeltaRef([string]$Layer, [string]$Path) {
    $kind = switch ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        '.txt' { 'text' } '.inf' { 'inf' } '.csv' { 'audit' } default { 'unknown' }
    }
    $disp = $Path
    if ($Path.StartsWith($ScriptRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $disp = $Path.Substring($ScriptRoot.Length).TrimStart('\')
    }
    return [pscustomobject]@{ Layer = $Layer; Path = $Path; Kind = $kind; Display = $disp }
}

function Get-DeltaFiles($Bl, [string]$ModeKey) {
    $out = New-Object System.Collections.Generic.List[object]

    # Lop 1: delta cua chinh Microsoft cho may non-domain-joined
    if ($ModeKey -like '*-nondomain') {
        $cfg = Join-Path $Bl.Path 'Scripts\ConfigFiles'
        foreach ($ext in @('.inf', '.txt')) {
            $p = Join-Path $cfg ('DeltaForNonDomainJoined' + $ext)
            if (Test-Path -LiteralPath $p -PathType Leaf) { $out.Add((New-DeltaRef 'microsoft' $p)) }
        }
    }

    # Lop 2-5: delta cua to chuc
    $layers = @(
        @{ L = 'common';                    D = (Join-Path $DeltaRoot 'common') },
        @{ L = $ModeKey;                    D = (Join-Path $DeltaRoot $ModeKey) },
        @{ L = "$($Bl.Name)\common";        D = (Join-Path (Join-Path $DeltaRoot $Bl.Name) 'common') },
        @{ L = "$($Bl.Name)\$ModeKey";      D = (Join-Path (Join-Path $DeltaRoot $Bl.Name) $ModeKey) }
    )
    foreach ($ly in $layers) {
        if (-not (Test-Path -LiteralPath $ly.D -PathType Container)) { continue }
        $files = @(Get-ChildItem -LiteralPath $ly.D -File |
                   Where-Object { $DeltaExtensions -contains $_.Extension.ToLowerInvariant() } |
                   Sort-Object Name)
        foreach ($f in $files) { $out.Add((New-DeltaRef $ly.L $f.FullName)) }
    }
    return $out.ToArray()
}

# Thu muc / file trong deltas\ ma script se KHONG BAO GIO ap (thuong do go sai ten)
function Get-IgnoredDeltaPaths($Baselines) {
    $bad = @()
    if (-not (Test-Path -LiteralPath $DeltaRoot -PathType Container)) { return $bad }
    $layerNames = @('common') + $ModeKeys
    $blNames = @($Baselines | ForEach-Object { $_.Name })

    $isDelta = { param($f) $DeltaExtensions -contains $f.Extension.ToLowerInvariant() }
    foreach ($f in @(Get-ChildItem -LiteralPath $DeltaRoot -File)) {
        if (& $isDelta $f) { $bad += "deltas\$($f.Name)" }
    }
    foreach ($d in @(Get-ChildItem -LiteralPath $DeltaRoot -Directory)) {
        if ($layerNames -contains $d.Name) { continue }
        if ($blNames -notcontains $d.Name) { $bad += "deltas\$($d.Name)\"; continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -File)) {
            if (& $isDelta $f) { $bad += "deltas\$($d.Name)\$($f.Name)" }
        }
        foreach ($s in @(Get-ChildItem -LiteralPath $d.FullName -Directory)) {
            if ($layerNames -notcontains $s.Name) { $bad += "deltas\$($d.Name)\$($s.Name)\" }
        }
    }
    return $bad
}

# ============================================================
# 5. Baseline tham chieu (.PolicyRules) = GPO cua mode + delta
#    Delta khong duoc them nhu 1 "GPO" rieng (Policy Analyzer se bao conflict),
#    ma THAY THE muc trung trong baseline -> file tham chieu khong co conflict.
# ============================================================
function Get-ChildText($Node, [string]$Name) {
    $c = $Node.SelectSingleNode($Name)
    if ($c) { return [string]$c.InnerText }
    return ''
}

function Get-RuleElements($Root) {
    return @($Root.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
}

function Get-SecName([string]$LineItem) {
    $eq = $LineItem.IndexOf('=')
    if ($eq -ge 0) { return $LineItem.Substring(0, $eq).Trim() }
    return $LineItem.Split(',')[0].Trim()
}

function ConvertTo-NormalGuid([string]$g) {
    $g = $g.Trim().Trim('{', '}').ToLowerInvariant()
    return '{' + $g + '}'
}

# "**del.<ten>" (DELETE) va "<ten>" cung dinh danh 1 setting
function Get-RegValueId([string]$v) {
    $l = $v.ToLowerInvariant()
    if ($l.StartsWith('**del.')) { $l = $l.Substring(6) }
    return $l
}

# Dinh danh 1 muc trong PolicyRules
function Get-RuleId($n) {
    switch ($n.LocalName) {
        { $_ -eq 'ComputerConfig' -or $_ -eq 'UserConfig' } {
            return ('REG|{0}|{1}|{2}' -f $n.LocalName, (Get-ChildText $n 'Key').ToLowerInvariant(),
                    (Get-RegValueId (Get-ChildText $n 'Value')))
        }
        'SecurityTemplate' {
            return ('SEC|{0}|{1}' -f $n.GetAttribute('Section').ToLowerInvariant(),
                    (Get-SecName (Get-ChildText $n 'LineItem')).ToLowerInvariant())
        }
        'AuditSubcategory' {
            return ('AUD|' + (ConvertTo-NormalGuid (Get-ChildText $n 'GUID')))
        }
    }
    return $null
}

function Get-AuditSettingText([string]$s) {
    switch ($s.Trim()) {
        '0' { return 'No Auditing' } '1' { return 'Success' }
        '2' { return 'Failure' }     '3' { return 'Success and Failure' }
    }
    return $s
}

# Gia tri cua 1 muc: Display (de doc) + Cmp (de so sanh)
function Get-RuleValue($n) {
    switch ($n.LocalName) {
        { $_ -eq 'ComputerConfig' -or $_ -eq 'UserConfig' } {
            $v = Get-ChildText $n 'Value'
            if ($v.StartsWith('**del.'))     { return [pscustomobject]@{ Display = 'DELETE (not configured)'; Cmp = 'delete' } }
            if ($v.StartsWith('**delvals.')) { return [pscustomobject]@{ Display = 'DELETE ALL VALUES'; Cmp = 'delvals' } }
            $d = '{0}:{1}' -f (Get-ChildText $n 'RegType'), (Get-ChildText $n 'RegData')
            return [pscustomobject]@{ Display = $d; Cmp = $d.ToLowerInvariant() }
        }
        'SecurityTemplate' {
            $li  = Get-ChildText $n 'LineItem'
            $eq  = $li.IndexOf('=')
            $val = if ($eq -ge 0) { $li.Substring($eq + 1).Trim() } else { $li.Trim() }
            $cmp = $val
            if ($n.GetAttribute('Section') -eq 'Privilege Rights') {
                # URA: so sanh nhu tap hop SID, khong phu thuoc thu tu
                $cmp = (@($val.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Sort-Object) -join ','
            }
            $disp = if ($val -eq '') { '(empty - granted to no one)' } else { $val }
            return [pscustomobject]@{ Display = $disp; Cmp = $cmp.ToLowerInvariant() }
        }
        'AuditSubcategory' {
            $s = Get-ChildText $n 'Setting'
            return [pscustomobject]@{ Display = (Get-AuditSettingText $s); Cmp = $s.Trim() }
        }
    }
    return [pscustomobject]@{ Display = ''; Cmp = '' }
}

function New-DeltaItem {
    param(
        [string]$Action, [string]$Target, [string]$Tag, $Attrs, $Fields,
        [string]$KeyLower, [string[]]$Subkeys, [string]$Note
    )
    return [pscustomobject]@{
        Action = $Action; Target = $Target; Tag = $Tag; Attrs = $Attrs; Fields = $Fields
        KeyLower = $KeyLower; Subkeys = $Subkeys; Note = $Note
    }
}

function ConvertTo-DecimalString([string]$s) {
    $s = $s.Trim()
    try {
        if ($s -match '^0[xX]([0-9A-Fa-f]+)$') { return ([Convert]::ToUInt64($Matches[1], 16)).ToString() }
        return ([UInt64]::Parse($s)).ToString()
    } catch {
        return $s
    }
}

# LGPO text: moi muc 4 dong (Configuration / Key / Value / Action), cach nhau
# bang dong trong hoac dong comment ';'
function Read-LgpoTextDelta([string]$Path) {
    $items = New-Object System.Collections.Generic.List[object]
    $lines = @(Get-Content -LiteralPath $Path | Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith(';') })
    if ($lines.Count % 4 -ne 0) {
        throw ("LGPO text entries must have 4 lines each; found {0} non-comment lines" -f $lines.Count)
    }
    for ($i = 0; $i -lt $lines.Count; $i += 4) {
        $cfg = $lines[$i].Trim(); $key = $lines[$i + 1].Trim(); $val = $lines[$i + 2].Trim(); $act = $lines[$i + 3].Trim()
        $target = "$cfg\$key\$val"
        $tag = $null
        if ($cfg -eq 'Computer') { $tag = 'ComputerConfig' } elseif ($cfg -eq 'User') { $tag = 'UserConfig' }

        if (-not $tag) {
            $items.Add((New-DeltaItem -Action 'skip' -Target $target -Note "MLGPO configuration '$cfg': applied by LGPO, not represented in the reference"))
        } elseif ($act -match '^(DWORD|QWORD|SZ|EXSZ|MULTISZ|BINARY):(.*)$') {
            $t = $Matches[1].ToUpperInvariant(); $d = $Matches[2]
            $type = @{ DWORD = 'REG_DWORD'; QWORD = 'REG_QWORD'; SZ = 'REG_SZ'; EXSZ = 'REG_EXPAND_SZ'; MULTISZ = 'REG_MULTI_SZ'; BINARY = 'REG_BINARY' }[$t]
            if ($t -eq 'DWORD' -or $t -eq 'QWORD') { $d = ConvertTo-DecimalString $d }
            $items.Add((New-DeltaItem -Action 'set' -Target $target -Tag $tag `
                -Fields ([ordered]@{ Key = $key; Value = $val; RegType = $type; RegData = $d })))
        } elseif ($act -eq 'DELETE') {
            $items.Add((New-DeltaItem -Action 'delete' -Target $target -Tag $tag `
                -Fields ([ordered]@{ Key = $key; Value = ('**del.' + $val); RegType = 'REG_SZ'; RegData = ' ' })))
        } elseif ($act -eq 'DELETEALLVALUES') {
            $items.Add((New-DeltaItem -Action 'delvals' -Target "$cfg\$key\*" -Tag $tag -KeyLower $key.ToLowerInvariant() `
                -Fields ([ordered]@{ Key = $key; Value = '**delvals.'; RegType = 'REG_SZ'; RegData = ' ' })))
        } elseif ($act -eq 'CLEAR') {
            $items.Add((New-DeltaItem -Action 'clear' -Target "$cfg\$key" -Tag $tag -KeyLower $key.ToLowerInvariant()))
        } elseif ($act -eq 'DELETEKEYS') {
            $subs = @($val.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $items.Add((New-DeltaItem -Action 'deletekeys' -Target "$cfg\$key\{$val}" -Tag $tag -KeyLower $key.ToLowerInvariant() -Subkeys $subs))
        } elseif ($act -eq 'CREATEKEY') {
            $items.Add((New-DeltaItem -Action 'skip' -Target $target -Note 'CREATEKEY: applied by LGPO, not represented in the reference'))
        } else {
            throw ("unknown action '{0}' for {1}" -f $act, $target)
        }
    }
    return $items.ToArray()
}

# Security template: [Section] + "Name = Value"
function Read-InfDelta([string]$Path) {
    $items = New-Object System.Collections.Generic.List[object]
    $skipSections = @('Unicode', 'Version', 'Profile Description')
    $section = $null
    foreach ($raw in @(Get-Content -LiteralPath $Path)) {
        $l = $raw.Trim()
        if ($l -eq '' -or $l.StartsWith(';')) { continue }
        if ($l -match '^\[(.+)\]$') { $section = $Matches[1].Trim(); continue }
        if (-not $section -or $skipSections -contains $section) { continue }

        $eq = $l.IndexOf('=')
        if ($eq -ge 0) {
            $line = '{0}={1}' -f $l.Substring(0, $eq).Trim(), $l.Substring($eq + 1).Trim()
        } else {
            $line = $l
        }
        $items.Add((New-DeltaItem -Action 'set' -Target ("[{0}] {1}" -f $section, (Get-SecName $line)) `
            -Tag 'SecurityTemplate' -Attrs @{ Section = $section } -Fields ([ordered]@{ LineItem = $line })))
    }
    return $items.ToArray()
}

# Advanced audit: dinh dang audit.csv cua auditpol /backup
function Read-AuditDelta([string]$Path) {
    $items = New-Object System.Collections.Generic.List[object]
    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -gt 0 -and -not ($rows[0].PSObject.Properties.Name -contains 'Subcategory GUID')) {
        throw "not an audit.csv file (missing 'Subcategory GUID' column)"
    }
    foreach ($r in $rows) {
        $guid = [string]$r.'Subcategory GUID'
        $name = [string]$r.Subcategory
        if (-not $guid.Trim()) {
            $items.Add((New-DeltaItem -Action 'skip' -Target "Audit option '$name'" -Note 'applied by LGPO, not represented in the reference'))
            continue
        }
        $items.Add((New-DeltaItem -Action 'set' -Target "Audit: $name" -Tag 'AuditSubcategory' `
            -Fields ([ordered]@{ GUID = (ConvertTo-NormalGuid $guid); Name = $name; Setting = ([string]$r.'Setting Value').Trim() })))
    }
    return $items.ToArray()
}

function New-RuleNode($Doc, $Item, [string]$PolicyName, [string]$SourceFile) {
    $e = $Doc.CreateElement($Item.Tag)
    if ($Item.Attrs) { foreach ($k in $Item.Attrs.Keys) { $e.SetAttribute($k, [string]$Item.Attrs[$k]) } }
    foreach ($k in $Item.Fields.Keys) {
        $c = $Doc.CreateElement($k); $c.InnerText = [string]$Item.Fields[$k]; [void]$e.AppendChild($c)
    }
    $c = $Doc.CreateElement('SourceFile'); $c.InnerText = $SourceFile; [void]$e.AppendChild($c)
    $c = $Doc.CreateElement('PolicyName'); $c.InnerText = $PolicyName; [void]$e.AppendChild($c)
    return $e
}

# Xoa cac muc khop: theo -Id, hoac theo -Tag + -KeyLower (them -Subtree = ca key con)
function Remove-RuleNodes {
    param($Root, [string]$Id, [string]$Tag, [string]$KeyLower, [switch]$Subtree)
    $count = 0
    foreach ($n in @(Get-RuleElements $Root)) {
        $hit = $false
        if ($Id) {
            $hit = ((Get-RuleId $n) -eq $Id)
        } elseif ($n.LocalName -eq $Tag) {
            $k = (Get-ChildText $n 'Key').ToLowerInvariant()
            $hit = ($k -eq $KeyLower) -or ($Subtree -and $k.StartsWith($KeyLower + '\'))
        }
        if ($hit) {
            $next = $n.NextSibling
            [void]$Root.RemoveChild($n)
            if ($next -and ($next.NodeType -eq [System.Xml.XmlNodeType]::Whitespace -or
                            $next.NodeType -eq [System.Xml.XmlNodeType]::SignificantWhitespace)) {
                [void]$Root.RemoveChild($next)
            }
            $count++
        }
    }
    return $count
}

function Add-RuleNode($Root, $Node) {
    [void]$Root.AppendChild($Node)
    [void]$Root.AppendChild($Root.OwnerDocument.CreateWhitespace("`r`n"))
}

function New-ReferencePolicyRules {
    param($Bl, [string]$ModeKey, $Gpos, $Deltas, [string[]]$ExcludedNames,
          [string]$OutFile, [string]$ReportFile)

    foreach ($f in @($OutFile, $ReportFile)) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }

    $rep = New-Object System.Collections.Generic.List[string]
    $cnt = [ordered]@{ OVERRIDE = 0; REMOVE = 0; NEW = 0; REDUNDANT = 0; INFO = 0; ERROR = 0 }
    $addLine = {
        param([string]$Status, [string]$Target, [string]$Detail, [string]$Source)
        $cnt[$Status]++
        $rep.Add(('[{0,-9}] {1}' -f $Status, $Target))
        if ($Detail) { $rep.Add(('            {0}' -f $Detail)) }
        $rep.Add(('            source: {0}' -f $Source))
    }

    $tmp    = Join-Path $env:TEMP ("baseline_ref_" + [guid]::NewGuid().ToString('N'))
    $stage  = Join-Path $tmp 'gpos'
    $rawOut = Join-Path $tmp 'base.PolicyRules'
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $ok = $false
    try {
        # GPO2PolicyRules nhan 1 thu muc chua nhieu GPO backup -> copy dung cac GPO cua mode
        foreach ($g in $Gpos) {
            Copy-Item -LiteralPath $g.Path -Destination (Join-Path $stage $g.Guid) -Recurse -Force
        }
        Invoke-Native -Exe $Gpo2RulesExe -Arguments @($stage, $rawOut) -Step 'REF-CONVERT' | Out-Null
        if (-not (Test-Path -LiteralPath $rawOut)) { throw 'GPO2PolicyRules did not produce a file' }

        $doc = New-Object System.Xml.XmlDocument
        $doc.PreserveWhitespace = $true
        $doc.Load($rawOut)
        $root = $doc.DocumentElement

        # Gia tri cua baseline GOC (truoc khi ap delta) de bao cao
        $baseVals = @{}
        foreach ($n in @(Get-RuleElements $root)) {
            $id = Get-RuleId $n
            if ($id) { $baseVals[$id] = Get-RuleValue $n }
        }
        $owner = @{}   # id -> file delta gan nhat da dat muc nay

        foreach ($d in $Deltas) {
            $items = @()
            try {
                switch ($d.Kind) {
                    'text'  { $items = @(Read-LgpoTextDelta $d.Path) }
                    'inf'   { $items = @(Read-InfDelta $d.Path) }
                    'audit' { $items = @(Read-AuditDelta $d.Path) }
                }
            } catch {
                & $addLine 'ERROR' $d.Display ("cannot parse: " + $_.Exception.Message) $d.Display
                continue
            }
            $policyName = 'DELTA ({0}) {1}' -f $d.Layer, [IO.Path]::GetFileName($d.Path)

            foreach ($it in $items) {
                if ($it.Action -eq 'skip') {
                    & $addLine 'INFO' $it.Target $it.Note $d.Display
                } elseif ($it.Action -eq 'clear' -or $it.Action -eq 'deletekeys') {
                    $removed = 0
                    if ($it.Action -eq 'clear') {
                        $removed = Remove-RuleNodes -Root $root -Tag $it.Tag -KeyLower $it.KeyLower -Subtree
                    } else {
                        foreach ($s in $it.Subkeys) {
                            $removed += Remove-RuleNodes -Root $root -Tag $it.Tag -KeyLower ($it.KeyLower + '\' + $s.ToLowerInvariant()) -Subtree
                        }
                    }
                    $st = if ($removed -gt 0) { 'REMOVE' } else { 'INFO' }
                    & $addLine $st $it.Target ("{0}: removed {1} item(s) from the reference" -f $it.Action.ToUpperInvariant(), $removed) $d.Display
                } else {
                    # set / delete / delvals: thay the muc trung, roi them muc cua delta
                    $node = New-RuleNode $doc $it $policyName $d.Path
                    $id   = Get-RuleId $node
                    $new  = Get-RuleValue $node
                    if ($it.Action -eq 'delvals') {
                        [void](Remove-RuleNodes -Root $root -Tag $it.Tag -KeyLower $it.KeyLower)
                    } else {
                        [void](Remove-RuleNodes -Root $root -Id $id)
                    }
                    Add-RuleNode $root $node

                    if ($baseVals.ContainsKey($id)) {
                        $b = $baseVals[$id]
                        if ($b.Cmp -eq $new.Cmp)          { $st = 'REDUNDANT' }
                        elseif ($it.Action -eq 'set')     { $st = 'OVERRIDE' }
                        else                              { $st = 'REMOVE' }
                        $detail = 'baseline: {0}  ->  delta: {1}' -f $b.Display, $new.Display
                    } else {
                        $st = 'NEW'
                        $detail = 'baseline: (not configured)  ->  delta: {0}' -f $new.Display
                    }
                    if ($owner.ContainsKey($id)) { $detail += ('   [replaces earlier delta {0}]' -f $owner[$id]) }
                    $owner[$id] = $d.Display
                    & $addLine $st $it.Target $detail $d.Display
                }
            }
        }

        $doc.Save($OutFile)
        $ok = $true
    } catch {
        # Khong dung ca phien audit vi loi o buoc tham chieu - ghi lai va di tiep
        Write-Host ("  -> [WARNING] Reference not built: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        $cnt.ERROR++
        $rep.Add(('[ERROR    ] reference .PolicyRules not built: {0}' -f $_.Exception.Message))
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # --- ghi delta report ---
    $hdr = New-Object System.Collections.Generic.List[string]
    $hdr.Add('=' * 70)
    $hdr.Add(' DELTA REPORT')
    $hdr.Add('=' * 70)
    $hdr.Add(' Baseline  : ' + $Bl.Name)
    $hdr.Add(' Mode      : ' + $ModeKey + ' (' + $ModeLabels[$ModeKey] + ')')
    $hdr.Add(' Modes from: ' + $Bl.Source)
    $hdr.Add(' Generated : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
    $hdr.Add((' GPOs ({0}):' -f @($Gpos).Count))
    foreach ($g in $Gpos) { $hdr.Add('   - ' + $g.Name + '  ' + $g.Guid) }
    if ($ExcludedNames) {
        $hdr.Add(' Excluded GPOs:')
        foreach ($n in $ExcludedNames) { $hdr.Add('   - ' + $n) }
    }
    $hdr.Add((' Delta files ({0}), applied in this order:' -f @($Deltas).Count))
    foreach ($d in $Deltas) { $hdr.Add(('   [{0}] {1}' -f $d.Layer, $d.Display)) }
    $hdr.Add('=' * 70)
    $hdr.Add(' Status legend:')
    $hdr.Add('   OVERRIDE  = delta changes a value set by the baseline')
    $hdr.Add('   REMOVE    = delta reverts a baseline setting to "not configured"')
    $hdr.Add('   NEW       = baseline does not configure this setting (review: still needed?)')
    $hdr.Add('   REDUNDANT = baseline already has this exact value (delta entry can be dropped)')
    $hdr.Add('   INFO      = applied by LGPO but not represented in the reference file')
    $hdr.Add('   ERROR     = delta file could not be parsed (LGPO will likely fail on it too)')
    $hdr.Add('=' * 70)
    $hdr.Add('')
    if ($rep.Count -eq 0) { $hdr.Add(' (no delta entries)') }
    $sum = New-Object System.Collections.Generic.List[string]
    $sum.Add('')
    $sum.Add('=' * 70)
    $sum.Add(' SUMMARY')
    $sum.Add('=' * 70)
    foreach ($k in $cnt.Keys) { $sum.Add((' {0,-10}: {1}' -f $k, $cnt[$k])) }
    if (-not $ok) { $sum.Add(' [WARNING] reference .PolicyRules was NOT written') }

    Set-Content -LiteralPath $ReportFile -Value (@($hdr) + @($rep) + @($sum)) -Encoding utf8
    $script:DeltaCounts = $cnt

    if ($ok) { Write-Host "  -> Created: $OutFile" -ForegroundColor Green }
    Write-Host "  -> Created: $ReportFile" -ForegroundColor Green
    Write-Host ("     OVERRIDE={0} REMOVE={1} NEW={2} REDUNDANT={3} INFO={4} ERROR={5}" -f `
        $cnt.OVERRIDE, $cnt.REMOVE, $cnt.NEW, $cnt.REDUNDANT, $cnt.INFO, $cnt.ERROR) `
        -ForegroundColor $(if ($cnt.ERROR -gt 0) { 'Red' } elseif ($cnt.NEW + $cnt.REDUNDANT -gt 0) { 'Yellow' } else { 'Gray' })
    return $ok
}

# ============================================================
# 6. Che do -List: chi liet ke, khong can quyen admin
# ============================================================
$Machine   = Get-MachineInfo
$Baselines = @(Get-Baselines)

if ($List) {
    Write-Host "======================================================================"
    Write-Host " MACHINE"
    Write-Host "======================================================================"
    Write-Host ("  {0} | {1} | DomainRole={2} ({3}) -> suggested mode: {4}" -f `
        $env:COMPUTERNAME, $Machine.Caption, $Machine.DomainRole, $Machine.RoleText, $Machine.SuggestedMode)
    if ($Baselines.Count -eq 0) {
        Write-Host "[ERROR] No baseline package with GPO backups found under $BaselineRoot" -ForegroundColor Red
        exit 1
    }
    foreach ($bl in $Baselines) {
        Write-Host ""
        Write-Host "======================================================================"
        $match = switch (Get-OsMatchScore $bl $Machine) { 2 { '  <- matches this OS' } 1 { '  <- same OS family, other version' } default { '' } }
        Write-Host (" {0}  [modes: {1}]{2}" -f $bl.Name, $bl.Source, $match) -ForegroundColor Cyan
        Write-Host "======================================================================"
        if ($bl.Error) { Write-Host "  [ERROR] $($bl.Error)" -ForegroundColor Red; continue }
        foreach ($m in $bl.Modes.Keys) {
            Write-Host ("  {0,-17} {1}" -f $m, $ModeLabels[$m]) -ForegroundColor Green
            foreach ($g in $bl.Modes[$m]) { Write-Host ("      GPO   {0}" -f $g.Name) }
            foreach ($d in @(Get-DeltaFiles $bl $m)) { Write-Host ("      DELTA [{0}] {1}" -f $d.Layer, $d.Display) -ForegroundColor DarkCyan }
        }
    }
    $ignored = @(Get-IgnoredDeltaPaths $Baselines)
    if ($ignored.Count -gt 0) {
        Write-Host ""
        Write-Host "[WARNING] These paths under deltas\ are never applied (check the folder names):" -ForegroundColor Yellow
        foreach ($p in $ignored) { Write-Host "    $p" -ForegroundColor Yellow }
    }
    exit 0
}

# ============================================================
# 7. Kiem tra dieu kien tien quyet
# ============================================================
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

# ============================================================
# 8. Xac dinh folder ket qua + <BASE>; lan dau thi chon goi + mode
#    - Lan dau : hoi ma nhan vien / IP, chon goi + mode -> tao folder audit_<BASE> moi
#    - -Recheck: chon 1 folder audit_* co san -> DUNG LAI <BASE> cu
#      (bat buoc dung lai BASE cu de bo file post_* trung ten voi bo pre_*)
# ============================================================
$SelBl = $null; $ModeKey = $null; $SelGpos = @(); $ExcludedNames = @(); $SelDeltas = @()
$SelBaselineText = '(unknown)'; $SelModeText = '(unknown)'

if ($Recheck) {
    $dirs = @(Get-ChildItem -LiteralPath $ScriptRoot -Directory -Filter 'audit_*' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending)
    if ($dirs.Count -eq 0) {
        Write-Host "[ERROR] No audit_* folder found in $ScriptRoot" -ForegroundColor Red
        Write-Host "        Run the script without -Recheck first to create one." -ForegroundColor Red
        exit 1
    }

    Write-Host "==== SELECT AUDIT FOLDER TO RECHECK ====" -ForegroundColor Cyan
    $idx      = Select-FromList -Title "Audit folders (newest first):" -Items @($dirs | ForEach-Object { $_.Name })
    $dirName  = $dirs[$idx].Name
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

    # Lay lai goi + mode da chon o lan dau tu delta_report
    $prevReport = Join-Path $AuditDir ("delta_report_" + $Tag + ".txt")
    if (Test-Path -LiteralPath $prevReport) {
        foreach ($l in @(Get-Content -LiteralPath $prevReport -TotalCount 12)) {
            if ($l -match '^ Baseline  : (.+)$') { $SelBaselineText = $Matches[1] }
            if ($l -match '^ Mode      : (.+)$') { $SelModeText = $Matches[1] }
        }
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
    $Hostname = $env:COMPUTERNAME
    Write-Host ""

    # ---------- chon goi baseline ----------
    $validBl = @($Baselines | Where-Object { -not $_.Error })
    foreach ($bl in @($Baselines | Where-Object { $_.Error })) {
        Write-Host "[WARNING] Skipping package '$($bl.Name)': $($bl.Error)" -ForegroundColor Yellow
    }
    if ($validBl.Count -eq 0) {
        Write-Host "[ERROR] No usable baseline package found under $BaselineRoot" -ForegroundColor Red
        exit 1
    }

    Write-Host ("Machine: {0} | DomainRole={1} ({2})" -f $Machine.Caption, $Machine.DomainRole, $Machine.RoleText) -ForegroundColor DarkGray
    if ($Baseline) {
        $SelBl = $validBl | Where-Object { $_.Name -eq $Baseline } | Select-Object -First 1
        if (-not $SelBl) {
            Write-Host "[ERROR] Baseline package '$Baseline' not found. Available:" -ForegroundColor Red
            foreach ($bl in $validBl) { Write-Host "        $($bl.Name)" -ForegroundColor Red }
            exit 1
        }
    } else {
        $scores = @($validBl | ForEach-Object { [int](Get-OsMatchScore $_ $Machine) })
        $default = 0; $best = 0
        for ($i = 0; $i -lt $scores.Count; $i++) {
            if ($scores[$i] -gt $best) { $best = $scores[$i]; $default = $i + 1 }
        }
        $items = @()
        for ($i = 0; $i -lt $validBl.Count; $i++) {
            $note = switch ($scores[$i]) { 2 { '  (matches this OS)' } 1 { '  (same OS family, other version)' } default { '' } }
            $items += ('{0}  [{1}]{2}' -f $validBl[$i].Name, (@($validBl[$i].Modes.Keys) -join ', '), $note)
        }
        Write-Host "==== SELECT BASELINE PACKAGE ====" -ForegroundColor Cyan
        $SelBl = $validBl[(Select-FromList -Title "Baseline packages in baseline_template\:" -Items $items -Default $default)]
    }
    Write-Host "Selected baseline: $($SelBl.Name)" -ForegroundColor Green
    Write-Host ""

    # ---------- chon mode ----------
    $modeList = @($SelBl.Modes.Keys)
    if ($Mode) {
        if ($modeList -notcontains $Mode) {
            Write-Host "[ERROR] Mode '$Mode' is not available in '$($SelBl.Name)'. Available: $($modeList -join ', ')" -ForegroundColor Red
            exit 1
        }
        $ModeKey = $Mode
    } else {
        $default = 0
        if ($Machine.SuggestedMode -and ($modeList -contains $Machine.SuggestedMode)) {
            $default = [array]::IndexOf($modeList, $Machine.SuggestedMode) + 1
        }
        $items = @($modeList | ForEach-Object { '{0,-17} {1}' -f $_, $ModeLabels[$_] })
        Write-Host "==== SELECT MODE ====" -ForegroundColor Cyan
        $ModeKey = $modeList[(Select-FromList -Title "Modes available in this package:" -Items $items -Default $default)]
    }
    Write-Host "Selected mode: $ModeKey" -ForegroundColor Green
    Write-Host ""

    # ---------- bo bot GPO (tuy chon) ----------
    $SelGpos = @($SelBl.Modes[$ModeKey])
    if (-not $PSBoundParameters.ContainsKey('Exclude')) {
        Write-Host "GPOs for this mode:" -ForegroundColor Cyan
        foreach ($g in $SelGpos) { Write-Host "  - $($g.Name)" }
        $ans = (Read-Host "Exclude GPOs? Enter keywords separated by ',' (e.g. Credential Guard,BitLocker), or Enter for none").Trim()
        $Exclude = @($ans.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    $warnings = New-Object System.Collections.Generic.List[string]
    if ($Exclude) {
        foreach ($p in $Exclude) {
            if (@($SelGpos | Where-Object { $_.Name -like "*$p*" }).Count -eq 0) {
                $warnings.Add("Exclude keyword '$p' matches no GPO of this mode.")
            }
        }
        $ExcludedNames = @($SelGpos | Where-Object { $n = $_.Name; @($Exclude | Where-Object { $n -like "*$_*" }).Count -gt 0 } |
                           ForEach-Object { $_.Name })
        $SelGpos = @($SelGpos | Where-Object { $ExcludedNames -notcontains $_.Name })
    }
    if ($SelGpos.Count -eq 0) {
        Write-Host "[ERROR] No GPO left to apply for mode '$ModeKey'." -ForegroundColor Red
        exit 1
    }

    $SelDeltas = @(Get-DeltaFiles $SelBl $ModeKey)

    # ---------- canh bao lech giua lua chon va may ----------
    $score = Get-OsMatchScore $SelBl $Machine
    if ($score -eq 0) {
        $warnings.Add(("Package '{0}' does not appear to target this OS ({1})." -f $SelBl.Name, $Machine.Caption))
    } elseif ($score -eq 1) {
        $warnings.Add(("Package '{0}' targets another version than this OS ({1})." -f $SelBl.Name, $Machine.Full))
    }
    if ($Machine.SuggestedMode -and $ModeKey -ne $Machine.SuggestedMode) {
        $warnings.Add(("Selected mode '{0}' differs from this machine's role ({1} -> '{2}')." -f $ModeKey, $Machine.RoleText, $Machine.SuggestedMode))
    }
    if ($ModeKey -like 'server-*' -and -not $Machine.IsServer) { $warnings.Add('Server mode selected on a client OS.') }
    if ($ModeKey -like 'client-*' -and $Machine.IsServer)      { $warnings.Add('Client mode selected on a server OS.') }
    if ($ModeKey -like '*-nondomain' -and @($SelDeltas | Where-Object { $_.Layer -eq 'microsoft' }).Count -eq 0) {
        $warnings.Add("Non-domain mode but the package has no Scripts\ConfigFiles\DeltaForNonDomainJoined.* files.")
    }
    foreach ($p in @(Get-IgnoredDeltaPaths $Baselines)) { $warnings.Add("Never applied (check folder name): $p") }

    # ---------- ke hoach ----------
    Write-Host ""
    Write-Host "======================================================================"
    Write-Host " PLAN"
    Write-Host "======================================================================"
    Write-Host ("  baseline    = {0}  (modes {1})" -f $SelBl.Name, $SelBl.Source)
    Write-Host ("  mode        = {0} - {1}" -f $ModeKey, $ModeLabels[$ModeKey])
    Write-Host ("  GPOs ({0})" -f $SelGpos.Count)
    foreach ($g in $SelGpos) { Write-Host "      $($g.Name)" }
    foreach ($n in $ExcludedNames) { Write-Host "      (excluded) $n" -ForegroundColor DarkGray }
    Write-Host ("  deltas ({0}), applied in this order after the GPOs" -f $SelDeltas.Count)
    foreach ($d in $SelDeltas) { Write-Host ("      [{0}] {1}" -f $d.Layer, $d.Display) }
    foreach ($w in $warnings) { Write-Host "  [WARNING] $w" -ForegroundColor Yellow }
    Write-Host ""
    if ($warnings.Count -gt 0) {
        if (-not (Read-YesNo "There are warnings above. Continue anyway?")) {
            Write-Host "==> Aborted, nothing was changed." -ForegroundColor DarkGray
            exit 1
        }
    }

    $SelBaselineText = $SelBl.Name
    $SelModeText     = '{0} ({1})' -f $ModeKey, $ModeLabels[$ModeKey]
    if ($ExcludedNames.Count -gt 0) { $SelModeText += ', excluded: ' + ($ExcludedNames -join '; ') }

    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $Tag = '{0}_{1}_{2}_{3}' -f (Format-Token $Hostname), (Format-Token $DeviceIp), $Timestamp, (Format-Token $EmpCode)

    $AuditDir = Join-Path $ScriptRoot ("audit_" + $Tag)
    New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null
    Write-Host "==> Created result folder: $AuditDir" -ForegroundColor Green
}

# ============================================================
# 9. Tien to file output: pre_ (lan dau) hoac post_ (recheck)
# ============================================================
if ($Recheck) { $Phase = 'post' } else { $Phase = 'pre' }
$SnapshotFile = Join-Path $AuditDir ($Phase + "_" + $Tag + ".PolicyRules")
$ReportPath   = Join-Path $AuditDir ($Phase + "_scriptcheck_" + $Tag + ".txt")
$RefFile      = Join-Path $AuditDir ("baseline_" + $Tag + ".PolicyRules")
$DeltaReport  = Join-Path $AuditDir ("delta_report_" + $Tag + ".txt")

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
Write-Host "  baseline    = $SelBaselineText"
Write-Host "  role mode   = $SelModeText"
Write-Host "  results     = $AuditDir"
if (-not $Recheck) {
    Write-Host ("  outputs     = {0}" -f [IO.Path]::GetFileName($RefFile))
    Write-Host ("                {0}" -f [IO.Path]::GetFileName($DeltaReport))
    Write-Host ("                {0}" -f [IO.Path]::GetFileName($SnapshotFile))
} else {
    Write-Host ("  outputs     = {0}" -f [IO.Path]::GetFileName($SnapshotFile))
}
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
# 10. [0] REFERENCE - baseline tham chieu + delta report (chi lan dau)
# ============================================================
$script:DeltaCounts = $null
if (-not $Recheck) {
    Write-Host "======================================================================"
    Write-Host " [0] REFERENCE BASELINE (selected GPOs + deltas)"
    Write-Host "======================================================================"
    New-ReferencePolicyRules -Bl $SelBl -ModeKey $ModeKey -Gpos $SelGpos -Deltas $SelDeltas `
        -ExcludedNames $ExcludedNames -OutFile $RefFile -ReportFile $DeltaReport | Out-Null
    Write-Host ""
}

# ============================================================
# 11. [1] SNAPSHOT policy hien tai
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
# 12. [2] SCRIPT CHECK security stack (Wazuh / MDE / Sysmon / command logging)
#     Giu nguyen nhu Apply-Baseline.ps1
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
Write-ReportLine -Text (' Baseline      : {0}' -f $SelBaselineText)
Write-ReportLine -Text (' Mode          : {0}' -f $SelModeText)
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
    # (KHONG dat ten $mode: trung voi tham so -Mode co ValidateSet, bien PS khong phan biet hoa thuong)
    $amMode = "$($mp.AMRunningMode)"
    if ($amMode -eq 'Normal') {
        Add-Result -Status PASS -Id 'MDE-007' -Title 'Defender AV is in active (not passive) mode' -Detail ("AMRunningMode={0}" -f $amMode)
    } elseif ($amMode -like '*Passive*' -or $amMode -like '*EDR Block*') {
        Add-Result -Status WARN -Id 'MDE-007' -Title 'Defender AV is in active (not passive) mode' -Detail ("AMRunningMode={0} (another AV is primary)" -f $amMode)
    } else {
        Add-Result -Status WARN -Id 'MDE-007' -Title 'Defender AV is in active (not passive) mode' -Detail ("AMRunningMode={0}" -f $amMode)
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
# 13. [3] REMEDIATE - ap baseline giong Baseline-LocalInstall.ps1 cua Microsoft,
#     roi ap tiep cac delta (thay doi cau hinh he thong)
# ==================================================================
$doRemediate = $false
if ($Recheck) {
    # Recheck chi de XAC NHAN hien trang sau khi da sua thu cong. Neu ap baseline
    # o day thi post_<BASE>.PolicyRules vua chup o buoc [1] khong con phan anh
    # dung hien trang nguoi lam audit vua sua.
    Write-Host "==> Recheck mode: the baseline is not applied." -ForegroundColor DarkGray
} elseif ($Machine.IsDC) {
    # Giong Baseline-LocalInstall.ps1: local policy tren DC bi GPO domain ghi de.
    Write-Host "======================================================================"
    Write-Host " [3] REMEDIATE - SKIPPED: this machine is a domain controller." -ForegroundColor Yellow
    Write-Host "     Applying the baseline to local policy is not supported on DCs."
    Write-Host "     Import the GPOs into AD instead (Scripts\Baseline-ADImport.ps1 in the"
    Write-Host "     baseline package), link them with GPMC, and turn the delta files into"
    Write-Host "     a domain GPO. baseline_$Tag.PolicyRules shows the expected result."
    Write-Host "======================================================================"
} else {
    Write-Host "======================================================================"
    Write-Host " [3] REMEDIATE - this will APPLY the selected baseline to this machine"
    Write-Host ("     baseline: {0}" -f $SelBl.Name)
    Write-Host ("     mode    : {0}" -f $ModeKey)
    Write-Host ("     {0} GPO(s), then {1} delta file(s)" -f $SelGpos.Count, $SelDeltas.Count)
    Write-Host "     Local Group Policy will be CHANGED. Logs -> lgpo.out / lgpo.err"
    Write-Host "======================================================================"
    if ($script:DeltaCounts -and $script:DeltaCounts.ERROR -gt 0) {
        Write-Host ("[WARNING] {0} delta file(s) could not be parsed - see {1}" -f `
            $script:DeltaCounts.ERROR, [IO.Path]::GetFileName($DeltaReport)) -ForegroundColor Yellow
    }
    if (Read-YesNo "Run remediation now?") {
        $doRemediate = $true
    } else {
        Write-Host "==> Skipping remediation." -ForegroundColor DarkGray
    }
}

if ($doRemediate) {
    Write-Host ""
    Write-Host "==> Applying baseline..." -ForegroundColor Cyan
    $script:LgpoOut = Join-Path $AuditDir 'lgpo.out'
    $script:LgpoErr = Join-Path $AuditDir 'lgpo.err'
    Set-Content -LiteralPath $script:LgpoOut -Value ("Baseline: {0} | Mode: {1} | {2}" -f $SelBl.Name, $SelModeText, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
    New-Item -ItemType File -Path $script:LgpoErr -Force | Out-Null
    $script:ApplyFailed = New-Object System.Collections.Generic.List[string]

    # Chay LGPO 1 buoc, gom stdout/stderr vao lgpo.out / lgpo.err (moi buoc 1 header)
    function Invoke-LgpoStep {
        param([string[]]$Arguments, [string]$Label)
        $o = [IO.Path]::GetTempFileName()
        $e = [IO.Path]::GetTempFileName()
        $code = 1
        try {
            $code = Invoke-Native -Exe $LgpoExe -Arguments $Arguments -StdoutFile $o -StderrFile $e -Step 'APPLY'
            Add-Content -LiteralPath $script:LgpoOut -Value @('', ('=' * 70), "[$Label]", ('LGPO.exe ' + ($Arguments -join ' ')), ('=' * 70))
            $so = Get-Content -LiteralPath $o -ErrorAction SilentlyContinue
            if ($so) { Add-Content -LiteralPath $script:LgpoOut -Value $so }
            $se = Get-Content -LiteralPath $e -ErrorAction SilentlyContinue
            if ($se -or $code -ne 0) {
                Add-Content -LiteralPath $script:LgpoErr -Value ("[{0}] exit code {1}" -f $Label, $code)
                if ($se) { Add-Content -LiteralPath $script:LgpoErr -Value $se }
            }
        } finally {
            Remove-Item -LiteralPath $o, $e -Force -ErrorAction SilentlyContinue
        }
        if ($code -ne 0) { $script:ApplyFailed.Add($Label) }
        return $code
    }

    # a) ADMX/ADML tuy chinh cua goi (de gpedit hien thi cac setting MSS / SecGuide)
    $tplDir = Join-Path $SelBl.Path 'Templates'
    if (Test-Path -LiteralPath $tplDir) {
        Write-Host "[APPLY] Copy custom administrative templates" -ForegroundColor DarkGray
        Copy-Item -Path (Join-Path $tplDir '*.admx') -Destination (Join-Path $env:windir 'PolicyDefinitions') -Force -ErrorAction SilentlyContinue
        Copy-Item -Path (Join-Path $tplDir 'en-US\*.adml') -Destination (Join-Path $env:windir 'PolicyDefinitions\en-US') -Force -ErrorAction SilentlyContinue
        Add-Content -LiteralPath $script:LgpoOut -Value ("Copied ADMX/ADML from {0}" -f $tplDir)
    }

    # b) Client side extensions - giong Baseline-LocalInstall.ps1
    Invoke-LgpoStep -Arguments @('/v', '/e', 'mitigation', '/e', 'audit', '/e', 'zone', '/e', 'DGVBS') -Label 'Client side extensions' | Out-Null

    # c) Tung GPO cua mode
    foreach ($g in $SelGpos) {
        Invoke-LgpoStep -Arguments @('/v', '/g', $g.Path) -Label ("GPO {0}" -f $g.Name) | Out-Null
    }

    # d) Delta theo thu tu lop (ghi sau thang)
    foreach ($d in $SelDeltas) {
        $sw = switch ($d.Kind) { 'text' { '/t' } 'inf' { '/s' } 'audit' { '/a' } }
        Invoke-LgpoStep -Arguments @('/v', $sw, $d.Path) -Label ("DELTA [{0}] {1}" -f $d.Layer, $d.Display) | Out-Null
    }

    # lam moi policy de co hieu luc (khong ghi log file)
    Invoke-Native -Exe 'gpupdate.exe' -Arguments @('/force') -Step 'GPUPDATE' | Out-Null
    Write-Host ""
    if ($script:ApplyFailed.Count -gt 0) {
        Write-Host "[WARNING] LGPO reported errors in these steps (see lgpo.err):" -ForegroundColor Yellow
        foreach ($s in $script:ApplyFailed) { Write-Host "    - $s" -ForegroundColor Yellow }
    }
    Write-Host "==> Baseline applied. Re-run this script with -Recheck to produce" -ForegroundColor Green
    Write-Host "    post_$Tag.PolicyRules and post_scriptcheck_$Tag.txt." -ForegroundColor Green
}

# ============================================================
# 14. Ket thuc
# ============================================================
Write-Host ""
Write-Host "======================================================================"
Write-Host " DONE"
Write-Host "======================================================================"
Get-ChildItem -LiteralPath $AuditDir -File | Sort-Object Name | ForEach-Object {
    Write-Host ("  " + $_.Name)
}
Write-Host "  -> result folder: $AuditDir"
Write-Host "Compare: open Policy Analyzer -> Add baseline_*, pre_* and post_* .PolicyRules -> View/Compare."
Write-Host "======================================================================"
