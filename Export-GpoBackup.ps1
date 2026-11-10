#Requires -Version 5.1
<#
    Export-GpoBackup.ps1
    --------------------
    Dong goi cac file trong deltas\ thanh mot GPO BACKUP co the import vao
    domain GPO (GPMC -> Import Settings, hoac Import-GPO).

    Vi sao can script nay: GPMC chi nhan GPO backup folder, KHONG nhan file
    .PolicyRules (dinh dang cua Policy Analyzer). Cac GPO cua Microsoft trong
    baseline_template\<goi>\GPOs\{GUID}\ VON DA la GPO backup -> import truc
    tiep bang baseline_template\<goi>\Scripts\Baseline-ADImport.ps1.
    Thieu duy nhat phan delta cua to chuc -> script nay tao ra no.

    MO HINH 2 LOP (giong thu tu ap local cua ApplyBaselinev2.ps1):
        1. Import cac GPO baseline cua Microsoft  (Baseline-ADImport.ps1)
        2. Import GPO delta nay, link voi Link Order 1 (uu tien CAO NHAT)
           -> delta ghi de baseline, dung nhu khi ap local.

    CHI ho tro mode domain-joined: client-domain, server-member, server-dc.
    Cac mode *-nondomain khong co y nghia voi domain GPO (domain GPO chi toi
    may da join domain), nen bi tu choi.

    FILE SINH RA (<OutDir>\<goi>_<mode>\{GUID}\):
        Backup.xml                                          metadata GPO
        bkupInfo.xml                                        metadata backup
        DomainSysvol\GPO\Machine\registry.pol               <- tu delta *.txt
        DomainSysvol\GPO\User\registry.pol                  <- neu delta co muc "User"
        DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf
                                                            <- tu delta *.inf
        DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv
                                                            <- tu delta *.csv
        BUILD-INFO.txt                                      liet ke nguon + ket qua self-check

    AI TAO FILE NAO:
        registry.pol  : LGPO.exe /r /w  (cong cu CUA MICROSOFT, khong tu dung tay)
        GptTmpl.inf   : script nay merge cac file .inf (text INI, de kiem tra)
        audit.csv     : script nay merge cac file .csv
        Backup.xml    : script nay sinh, theo DUNG template nhung trong chinh
                        LGPO.exe va doi chieu voi Backup.xml that cua baseline
                        (cung thu tu element, cung 3 khoi GroupPolicyExtension).

    SELF-CHECK: sau khi build, script chay "LGPO.exe /parse /m registry.pol"
    - tuc la de LGPO doc lai chinh file no vua ghi - roi so voi danh sach
    setting mong doi. Lech thi bao do.

    !!! BAT BUOC KIEM TRA TRUOC KHI DUNG THAT !!!
    Loi dinh dang Backup.xml KHONG bao loi khi import: GPMC bao thanh cong
    nhung AM THAM bo setting. Vi vay luon lam buoc nay trong domain test /
    tren mot GPO rac truoc:
        Import-GPO -BackupId '{GUID}' -Path '<OutDir>\<goi>_<mode>' `
                   -TargetName 'TEST Delta' -CreateIfNeeded
        Get-GPOReport -Name 'TEST Delta' -ReportType Html -Path .\test.html
    Mo test.html, doi chieu TUNG setting voi exports\<goi>_<mode>_delta_report.txt
    (sinh boi ApplyBaselinev2.ps1 -Export). Chi khi khop het moi dung that.

    Tham so:
        -Baseline <ten thu muc>  goi trong baseline_template\ (bo qua menu)
        -Mode <mode>             client-domain | server-member | server-dc
        -Name <ten GPO>          ten hien thi cua GPO (mac dinh: "ORG Delta - <goi> <mode>")
        -OutDir <thu muc>        mac dinh .\exports\gpo
        -All                     xuat moi to hop goi x mode domain co delta
        -List                    chi liet ke, khong tao file

    Yeu cau: LGPO.exe trong .\LGPO\. KHONG can quyen Administrator.
#>
[CmdletBinding()]
param(
    [string]$Baseline,
    [ValidateSet('client-domain', 'server-member', 'server-dc')]
    [string]$Mode,
    [string]$Name,
    [string]$OutDir,
    [switch]$All,
    [switch]$List
)

$ErrorActionPreference = 'Stop'

# ============================================================
# 1. Duong dan + hang so
# ============================================================
$ScriptRoot   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LgpoExe      = Join-Path $ScriptRoot 'LGPO\LGPO.exe'
$BaselineRoot = Join-Path $ScriptRoot 'baseline_template'
$DeltaRoot    = Join-Path $ScriptRoot 'deltas'

# Chi mode domain-joined moi co nghia voi domain GPO
$DomainModes     = @('client-domain', 'server-member', 'server-dc')
$DeltaExtensions = @('.txt', '.inf', '.csv')

# Client Side Extension (CSE) GUID -> ghi vao MachineExtensionGuids cua Backup.xml.
# GUID dau moi nhom [] la CSE (quyet dinh client co xu ly setting hay khong),
# cac GUID sau la tool/snap-in (chi mang tinh thong tin).
# Lay tu Backup.xml that cua baseline va tu template trong LGPO.exe.
$CseRegistry = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
$CseSecurity = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
$CseAudit    = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

# ============================================================
# 2. Ham dung chung
# ============================================================
function Format-Token([string]$s) {
    return ($s -replace '[\\/:*?"<>|\s]', '-')
}

function Select-FromList {
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string[]]$Items)
    Write-Host $Title -ForegroundColor Cyan
    for ($i = 0; $i -lt $Items.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $Items[$i])
    }
    do {
        $sel = (Read-Host ("Select a number [1-{0}]" -f $Items.Count)).Trim()
        $ok = ($sel -match '^\d+$') -and ([int]$sel -ge 1) -and ([int]$sel -le $Items.Count)
        if (-not $ok) { Write-Host "    Invalid choice, please try again." -ForegroundColor Yellow }
    } until ($ok)
    return ([int]$sel - 1)
}

# Chay LGPO.exe, tra ve @{ Code; Out; Err }
function Invoke-Lgpo {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $o = [IO.Path]::GetTempFileName()
    $e = [IO.Path]::GetTempFileName()
    $code = 1
    try {
        $argLine = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
        $p = Start-Process -FilePath $LgpoExe -ArgumentList $argLine -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $o -RedirectStandardError $e
        $code = $p.ExitCode
        return [pscustomobject]@{
            Code = $code
            Out  = (Get-Content -LiteralPath $o -Raw -ErrorAction SilentlyContinue)
            Err  = (Get-Content -LiteralPath $e -Raw -ErrorAction SilentlyContinue)
        }
    } finally {
        Remove-Item -LiteralPath $o, $e -Force -ErrorAction SilentlyContinue
    }
}

# Ghi text thuan UTF-8 KHONG BOM (dinh dang LGPO text, giong cac file delta *.txt)
function Write-PlainText([string]$Path, [string[]]$Lines) {
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, (($Lines -join "`r`n") + "`r`n"), $enc)
}

# ============================================================
# 3. Phat hien goi baseline + delta
#    Get-DeltaFiles PHAI giong het logic trong ApplyBaselinev2.ps1, neu khong
#    GPO sinh ra se khac voi baseline tham chieu (.PolicyRules). Khi sua mot
#    ben, sua ca ben kia.
# ============================================================
function Get-BaselinePackages {
    $names = @()
    foreach ($root in @($BaselineRoot, $DeltaRoot)) {
        if (Test-Path -LiteralPath $root -PathType Container) {
            $names += @(Get-ChildItem -LiteralPath $root -Directory |
                        Where-Object { $_.Name -ne 'common' -and $DomainModes -notcontains $_.Name } |
                        ForEach-Object { $_.Name })
        }
    }
    return @($names | Sort-Object -Unique)
}

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

# Cac lop delta - KHONG co lop 'microsoft' (DeltaForNonDomainJoined) vi script
# nay chi lam mode domain-joined.
function Get-DeltaFiles([string]$PkgName, [string]$ModeKey) {
    $out = New-Object System.Collections.Generic.List[object]
    $layers = @(
        @{ L = 'common';                 D = (Join-Path $DeltaRoot 'common') },
        @{ L = $ModeKey;                 D = (Join-Path $DeltaRoot $ModeKey) },
        @{ L = "$PkgName\common";        D = (Join-Path (Join-Path $DeltaRoot $PkgName) 'common') },
        @{ L = "$PkgName\$ModeKey";      D = (Join-Path (Join-Path $DeltaRoot $PkgName) $ModeKey) }
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

# ============================================================
# 4. Doc / gop cac file delta
# ============================================================

# LGPO text: moi muc 4 dong (Configuration / Key / Value / Action)
function Read-LgpoTextRecords([string]$Path) {
    $lines = @(Get-Content -LiteralPath $Path |
               Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith(';') })
    if ($lines.Count % 4 -ne 0) {
        throw ("{0}: LGPO text entries must have 4 lines each; found {1} non-comment lines" -f $Path, $lines.Count)
    }
    $recs = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $lines.Count; $i += 4) {
        $recs.Add([pscustomobject]@{
            Config = $lines[$i].Trim()
            Key    = $lines[$i + 1].Trim()
            Value  = $lines[$i + 2].Trim()
            Action = $lines[$i + 3].Trim()
        })
    }
    return $recs.ToArray()
}

# Gop nhieu file LGPO text; muc trung (Config|Key|Value) thi file SAU thang.
# Tra ve @{ Machine; User; Unsupported }
function Merge-LgpoText($TextDeltas) {
    $map = [ordered]@{}
    $unsupported = New-Object System.Collections.Generic.List[string]
    foreach ($d in $TextDeltas) {
        foreach ($r in (Read-LgpoTextRecords $d.Path)) {
            if ($r.Config -ne 'Computer' -and $r.Config -ne 'User') {
                $unsupported.Add(("{0}: configuration '{1}' (MLGPO) is local-only, skipped" -f $d.Display, $r.Config))
                continue
            }
            if ($r.Action -eq 'CLEAR' -or $r.Action -eq 'DELETEKEYS') {
                $unsupported.Add(("{0}: action '{1}' on {2} cannot be represented in registry.pol, skipped" -f `
                    $d.Display, $r.Action, $r.Key))
                continue
            }
            $id = ('{0}|{1}|{2}' -f $r.Config, $r.Key, $r.Value).ToLowerInvariant()
            $map[$id] = $r
        }
    }
    $all = @($map.Values)
    return [pscustomobject]@{
        Machine     = @($all | Where-Object { $_.Config -eq 'Computer' })
        User        = @($all | Where-Object { $_.Config -eq 'User' })
        Unsupported = $unsupported.ToArray()
    }
}

function ConvertTo-LgpoTextLines($Records) {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Records) {
        $lines.Add($r.Config); $lines.Add($r.Key); $lines.Add($r.Value); $lines.Add($r.Action)
        $lines.Add('')
    }
    return $lines.ToArray()
}

# Security template: gop theo section, key trung thi file SAU thang.
# Giong semantics khi LGPO /s ap lan luot tung file.
function Merge-InfFiles($InfDeltas) {
    $sections = [ordered]@{}           # section -> ordered{ keyLower -> 'Key = Value' }
    $skip = @('unicode', 'version', 'profile description')
    foreach ($d in $InfDeltas) {
        $section = $null
        foreach ($raw in @(Get-Content -LiteralPath $d.Path)) {
            $l = $raw.Trim()
            if ($l -eq '' -or $l.StartsWith(';')) { continue }
            if ($l -match '^\[(.+)\]$') { $section = $Matches[1].Trim(); continue }
            if (-not $section -or $skip -contains $section.ToLowerInvariant()) { continue }
            if (-not $sections.Contains($section)) { $sections[$section] = [ordered]@{} }

            $eq = $l.IndexOf('=')
            if ($eq -ge 0) {
                $k = $l.Substring(0, $eq).Trim()
                $v = $l.Substring($eq + 1).Trim()
                $sections[$section][$k.ToLowerInvariant()] = ('{0} = {1}' -f $k, $v)
            } else {
                $sections[$section][$l.ToLowerInvariant()] = $l
            }
        }
    }
    if ($sections.Count -eq 0) { return $null }

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('[Unicode]'); $out.Add('Unicode=yes')
    foreach ($s in $sections.Keys) {
        $out.Add(('[{0}]' -f $s))
        foreach ($line in $sections[$s].Values) { $out.Add($line) }
    }
    $out.Add('[Version]'); $out.Add('signature="$CHICAGO$"'); $out.Add('Revision=1')
    return $out.ToArray()
}

# Advanced audit: gop theo "Subcategory GUID", dong trung thi file SAU thang.
function Merge-AuditCsv($CsvDeltas) {
    $header = $null
    $rows = [ordered]@{}
    foreach ($d in $CsvDeltas) {
        $lines = @(Get-Content -LiteralPath $d.Path | Where-Object { $_.Trim() -ne '' })
        if ($lines.Count -eq 0) { continue }
        if (-not $header) { $header = $lines[0] }
        $parsed = @(Import-Csv -LiteralPath $d.Path)
        if ($parsed.Count -gt 0 -and -not ($parsed[0].PSObject.Properties.Name -contains 'Subcategory GUID')) {
            throw ("{0}: not an audit.csv (missing 'Subcategory GUID' column)" -f $d.Display)
        }
        for ($i = 1; $i -lt $lines.Count; $i++) {
            $cols = $lines[$i].Split(',')
            $guid = if ($cols.Count -ge 4) { $cols[3].Trim().ToLowerInvariant() } else { $lines[$i] }
            $rows[$guid] = $lines[$i]
        }
    }
    if (-not $header -or $rows.Count -eq 0) { return $null }
    return @($header) + @($rows.Values)
}

# ============================================================
# 5. Sinh Backup.xml / bkupInfo.xml
#    Cau truc lay tu template nhung trong LGPO.exe, da doi chieu voi
#    Backup.xml that cua baseline: cung thu tu element trong
#    GroupPolicyCoreSettings (ID, Domain, SecurityDescriptor, DisplayName,
#    Options, UserVersionNumber, MachineVersionNumber, MachineExtensionGuids,
#    UserExtensionGuids, WMIFilter) va cung 3 khoi GroupPolicyExtension.
# ============================================================

# Security descriptor dang hex, sinh tu SDDL chi dung SID well-known ->
# khong phu thuoc domain nao. GPMC "Import Settings" khong ap SD nay (SD chi
# dung cho Restore), nhung schema cua Backup.xml van yeu cau co.
function New-GpoSecurityDescriptorHex {
    $sddl = 'O:BAG:BAD:PAI(A;CI;LCRPLORC;;;AU)(A;CI;LCRPLORC;;;ED)' +
            '(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)'
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
    $bytes = New-Object byte[] $sd.BinaryLength
    $sd.GetBinaryForm($bytes, 0)
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join ' ')
}

function New-BackupXml {
    param(
        [Parameter(Mandatory)][string]$GpoGuid,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][bool]$HasMachineRegistry,
        [Parameter(Mandatory)][bool]$HasUserRegistry,
        [Parameter(Mandatory)][bool]$HasSecurity,
        [Parameter(Mandatory)][bool]$HasAudit
    )
    $sdHex  = New-GpoSecurityDescriptorHex
    $domain = 'placeholder.local'   # bi bo qua boi Import Settings

    # --- MachineExtensionGuids: chi khai bao CSE co payload, sap xep tang dan ---
    $cses = @()
    if ($HasMachineRegistry -or $HasUserRegistry) { $cses += $CseRegistry }
    if ($HasSecurity)                             { $cses += $CseSecurity }
    if ($HasAudit)                                { $cses += $CseAudit }
    $machineExt = ($cses | Sort-Object) -join ''

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<?xml version="1.0" encoding="utf-8"?>')
    [void]$sb.Append('<!-- Generated by Export-GpoBackup.ps1 -->')
    [void]$sb.Append('<GroupPolicyBackupScheme bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate"')
    [void]$sb.Append(' xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations"')
    [void]$sb.Append(' xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations">')
    [void]$sb.Append('<GroupPolicyObject><SecurityGroups/><FilePaths/><GroupPolicyCoreSettings>')
    [void]$sb.Append(('<ID><![CDATA[{0}]]></ID>' -f $GpoGuid))
    [void]$sb.Append(('<Domain><![CDATA[{0}]]></Domain>' -f $domain))
    [void]$sb.Append(('<SecurityDescriptor>{0}</SecurityDescriptor>' -f $sdHex))
    [void]$sb.Append(('<DisplayName><![CDATA[{0}]]></DisplayName>' -f $DisplayName))
    [void]$sb.Append('<Options><![CDATA[0]]></Options>')
    [void]$sb.Append('<UserVersionNumber><![CDATA[0]]></UserVersionNumber>')
    [void]$sb.Append('<MachineVersionNumber><![CDATA[1]]></MachineVersionNumber>')
    [void]$sb.Append(('<MachineExtensionGuids><![CDATA[{0}]]></MachineExtensionGuids>' -f $machineExt))
    [void]$sb.Append('<UserExtensionGuids/><WMIFilter/></GroupPolicyCoreSettings>')

    # --- Registry extension ---
    if ($HasMachineRegistry -or $HasUserRegistry) {
        [void]$sb.Append('<GroupPolicyExtension bkp:ID="{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" bkp:DescName="Registry">')
        if ($HasMachineRegistry) {
            [void]$sb.Append('<FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\registry.pol"' +
                             ' bkp:Location="DomainSysvol\GPO\Machine\registry.pol"/>')
        }
        if ($HasUserRegistry) {
            [void]$sb.Append('<FSObjectFile bkp:Path="%GPO_USER_FSPATH%\registry.pol"' +
                             ' bkp:Location="DomainSysvol\GPO\User\registry.pol"/>')
        }
        [void]$sb.Append('</GroupPolicyExtension>')
    }

    # --- Security extension (GptTmpl.inf) ---
    if ($HasSecurity) {
        [void]$sb.Append('<GroupPolicyExtension bkp:ID="{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" bkp:DescName="Security">')
        [void]$sb.Append('<FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\microsoft\windows nt\SecEdit\GptTmpl.inf"' +
                         ' bkp:ReEvaluateFunction="SecurityValidateSettings"' +
                         ' bkp:Location="DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"/>')
        [void]$sb.Append('</GroupPolicyExtension>')
    }

    # --- audit.csv: GPMC/LGPO dat trong khoi "Unknown Extension" ---
    if ($HasAudit) {
        [void]$sb.Append('<GroupPolicyExtension bkp:ID="{F15C46CD-82A0-4C2D-A210-5D0D3182A418}" bkp:DescName="Unknown Extension">')
        foreach ($d in @('Microsoft', 'Microsoft\Windows NT', 'Microsoft\Windows NT\Audit')) {
            [void]$sb.Append(('<FSObjectDir bkp:Path="%GPO_MACH_FSPATH%\{0}" bkp:Location="DomainSysvol\GPO\Machine\{0}"/>' -f $d))
        }
        [void]$sb.Append('<FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\Microsoft\Windows NT\Audit\audit.csv"' +
                         ' bkp:Location="DomainSysvol\GPO\Machine\Microsoft\Windows NT\Audit\audit.csv"/>')
        [void]$sb.Append('</GroupPolicyExtension>')
    }

    [void]$sb.Append('</GroupPolicyObject></GroupPolicyBackupScheme>')
    return $sb.ToString()
}

function New-BkupInfoXml {
    param([Parameter(Mandatory)][string]$GpoGuid, [Parameter(Mandatory)][string]$BackupId,
          [Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][string]$TimeStamp)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">')
    [void]$sb.Append(('<GPOGuid><![CDATA[{0}]]></GPOGuid>' -f $GpoGuid))
    [void]$sb.Append('<GPODomain><![CDATA[placeholder.local]]></GPODomain>')
    [void]$sb.Append('<GPODomainGuid><![CDATA[{00000000-0000-0000-0000-000000000000}]]></GPODomainGuid>')
    [void]$sb.Append('<GPODomainController><![CDATA[none]]></GPODomainController>')
    [void]$sb.Append(('<BackupTime><![CDATA[{0}]]></BackupTime>' -f $TimeStamp))
    [void]$sb.Append(('<ID><![CDATA[{0}]]></ID>' -f $BackupId))
    [void]$sb.Append('<Comment><![CDATA[Delta GPO built by Export-GpoBackup.ps1]]></Comment>')
    [void]$sb.Append(('<GPODisplayName><![CDATA[{0}]]></GPODisplayName>' -f $DisplayName))
    [void]$sb.Append('</BackupInst>')
    return $sb.ToString()
}

# ============================================================
# 6. Build 1 to hop goi x mode
# ============================================================
function New-DeltaGpoBackup {
    param([Parameter(Mandatory)][string]$PkgName, [Parameter(Mandatory)][string]$ModeKey,
          [Parameter(Mandatory)][string]$GpoName, [Parameter(Mandatory)][string]$Dir)

    $deltas = @(Get-DeltaFiles $PkgName $ModeKey)
    if ($deltas.Count -eq 0) {
        Write-Host ("  [SKIP] {0} / {1}: no delta files" -f $PkgName, $ModeKey) -ForegroundColor Yellow
        return $null
    }

    $txt = @($deltas | Where-Object { $_.Kind -eq 'text' })
    $inf = @($deltas | Where-Object { $_.Kind -eq 'inf' })
    $csv = @($deltas | Where-Object { $_.Kind -eq 'audit' })

    Write-Host ""
    Write-Host ("---- {0} / {1} ----" -f $PkgName, $ModeKey) -ForegroundColor Cyan
    foreach ($d in $deltas) { Write-Host ("       [{0}] {1}" -f $d.Layer, $d.Display) -ForegroundColor DarkCyan }

    # --- thu muc dich ---
    $gpoGuid  = '{' + ([guid]::NewGuid().ToString().ToUpperInvariant()) + '}'
    $backupId = '{' + ([guid]::NewGuid().ToString().ToUpperInvariant()) + '}'
    $root     = Join-Path $Dir ('{0}_{1}' -f (Format-Token $PkgName), (Format-Token $ModeKey))
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    $bak      = Join-Path $root $gpoGuid
    $machDir  = Join-Path $bak 'DomainSysvol\GPO\Machine'
    $userDir  = Join-Path $bak 'DomainSysvol\GPO\User'
    $secDir   = Join-Path $machDir 'microsoft\windows nt\SecEdit'
    $audDir   = Join-Path $machDir 'microsoft\windows nt\Audit'
    foreach ($d in @($machDir, $userDir)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

    $notes  = New-Object System.Collections.Generic.List[string]
    $checks = New-Object System.Collections.Generic.List[string]

    # --- registry.pol qua LGPO.exe /r /w ---
    $hasMach = $false; $hasUser = $false
    $merged  = $null
    if ($txt.Count -gt 0) {
        $merged = Merge-LgpoText $txt
        foreach ($u in $merged.Unsupported) { $notes.Add("UNSUPPORTED: $u") }

        foreach ($side in @(
            @{ Recs = $merged.Machine; Pol = (Join-Path $machDir 'registry.pol'); Label = 'Machine'; Switch = '/m' },
            @{ Recs = $merged.User;    Pol = (Join-Path $userDir 'registry.pol'); Label = 'User';    Switch = '/u' })) {

            if (@($side.Recs).Count -eq 0) { continue }
            $tmpTxt = Join-Path $env:TEMP ("lgpo_build_" + [guid]::NewGuid().ToString('N') + ".txt")
            try {
                Write-PlainText $tmpTxt (ConvertTo-LgpoTextLines $side.Recs)
                $r = Invoke-Lgpo -Arguments @('/r', $tmpTxt, '/w', $side.Pol)
                if ($r.Code -ne 0 -or -not (Test-Path -LiteralPath $side.Pol)) {
                    throw ("LGPO /r /w failed for {0} (exit {1}): {2}" -f $side.Label, $r.Code, ($r.Err + $r.Out))
                }
                Write-Host ("       built {0}\registry.pol  ({1} setting(s))" -f $side.Label, @($side.Recs).Count) -ForegroundColor Green
                if ($side.Label -eq 'Machine') { $hasMach = $true } else { $hasUser = $true }

                # --- SELF-CHECK: de LGPO doc lai chinh file no vua ghi ---
                # /parse phai la directive dau tien; /q de khong in header.
                $p = Invoke-Lgpo -Arguments @('/parse', '/q', $side.Switch, $side.Pol)
                if ($p.Code -ne 0) {
                    $checks.Add(("{0}: /parse failed (exit {1})" -f $side.Label, $p.Code))
                } else {
                    $back = @()
                    $plines = @(($p.Out -split "`r?`n") |
                                Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith(';') })
                    for ($i = 0; ($i + 4) -le $plines.Count; $i += 4) {
                        $back += ('{0}|{1}|{2}' -f $plines[$i].Trim(), $plines[$i+1].Trim(), $plines[$i+2].Trim()).ToLowerInvariant()
                    }
                    $want = @($side.Recs | ForEach-Object { ('{0}|{1}|{2}' -f $_.Config, $_.Key, $_.Value).ToLowerInvariant() })
                    $missing = @($want | Where-Object { $back -notcontains $_ })
                    $extra   = @($back | Where-Object { $want -notcontains $_ })
                    if ($missing.Count -eq 0 -and $extra.Count -eq 0) {
                        $checks.Add(("{0}: OK - {1}/{1} settings read back by LGPO /parse" -f $side.Label, $want.Count))
                        Write-Host ("       self-check {0}: OK ({1} settings)" -f $side.Label, $want.Count) -ForegroundColor Green
                    } else {
                        $checks.Add(("{0}: MISMATCH - {1} missing, {2} unexpected" -f $side.Label, $missing.Count, $extra.Count))
                        foreach ($m in $missing) { $checks.Add("    missing:    $m") }
                        foreach ($m in $extra)   { $checks.Add("    unexpected: $m") }
                        Write-Host ("       self-check {0}: MISMATCH ({1} missing, {2} unexpected)" -f `
                            $side.Label, $missing.Count, $extra.Count) -ForegroundColor Red
                    }
                }
            } finally {
                Remove-Item -LiteralPath $tmpTxt -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # --- GptTmpl.inf ---
    $hasSec = $false
    if ($inf.Count -gt 0) {
        $infLines = Merge-InfFiles $inf
        if ($infLines) {
            New-Item -ItemType Directory -Path $secDir -Force | Out-Null
            # Unicode (UTF-16LE + BOM), giong dinh dang .inf cua Microsoft
            Set-Content -LiteralPath (Join-Path $secDir 'GptTmpl.inf') -Value $infLines -Encoding Unicode
            $hasSec = $true
            $n = @($infLines | Where-Object { $_ -match '=' -and $_ -notmatch '^\[' }).Count
            Write-Host ("       built GptTmpl.inf  ({0} line(s))" -f $n) -ForegroundColor Green
        }
    }

    # --- audit.csv ---
    $hasAud = $false
    if ($csv.Count -gt 0) {
        $csvLines = Merge-AuditCsv $csv
        if ($csvLines) {
            New-Item -ItemType Directory -Path $audDir -Force | Out-Null
            Write-PlainText (Join-Path $audDir 'audit.csv') $csvLines
            $hasAud = $true
            Write-Host ("       built audit.csv  ({0} row(s))" -f ($csvLines.Count - 1)) -ForegroundColor Green
        }
    }

    if (-not ($hasMach -or $hasUser -or $hasSec -or $hasAud)) {
        Write-Host ("  [SKIP] {0} / {1}: delta files produced no settings" -f $PkgName, $ModeKey) -ForegroundColor Yellow
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        return $null
    }

    # LGPO /r khong tao file rong -> xoa thu muc User neu khong dung
    if (-not $hasUser) { Remove-Item -LiteralPath $userDir -Recurse -Force -ErrorAction SilentlyContinue }

    # --- Backup.xml + bkupInfo.xml ---
    $stamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    $enc   = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $bak 'Backup.xml'),
        (New-BackupXml -GpoGuid $gpoGuid -DisplayName $GpoName -HasMachineRegistry $hasMach `
                       -HasUserRegistry $hasUser -HasSecurity $hasSec -HasAudit $hasAud), $enc)
    [System.IO.File]::WriteAllText((Join-Path $bak 'bkupInfo.xml'),
        (New-BkupInfoXml -GpoGuid $gpoGuid -BackupId $backupId -DisplayName $GpoName -TimeStamp $stamp), $enc)
    Write-Host "       built Backup.xml + bkupInfo.xml" -ForegroundColor Green

    # --- BUILD-INFO.txt ---
    $info = New-Object System.Collections.Generic.List[string]
    $info.Add('=' * 70)
    $info.Add(' DELTA GPO BACKUP - BUILD INFO')
    $info.Add('=' * 70)
    $info.Add(' Package     : ' + $PkgName)
    $info.Add(' Mode        : ' + $ModeKey)
    $info.Add(' GPO name    : ' + $GpoName)
    $info.Add(' Backup GUID : ' + $gpoGuid)
    $info.Add(' Generated   : ' + $stamp)
    $info.Add('')
    $info.Add(' Source delta files, in apply order (later wins):')
    foreach ($d in $deltas) { $info.Add(('   [{0}] {1}' -f $d.Layer, $d.Display)) }
    $info.Add('')
    $info.Add(' Payload written:')
    if ($hasMach) { $info.Add('   DomainSysvol\GPO\Machine\registry.pol') }
    if ($hasUser) { $info.Add('   DomainSysvol\GPO\User\registry.pol') }
    if ($hasSec)  { $info.Add('   DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf') }
    if ($hasAud)  { $info.Add('   DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv') }
    $info.Add('')
    $info.Add(' SELF-CHECK (LGPO.exe /parse reading back its own registry.pol):')
    if ($checks.Count -eq 0) { $info.Add('   (no registry payload)') }
    foreach ($c in $checks) { $info.Add('   ' + $c) }
    if ($notes.Count -gt 0) {
        $info.Add('')
        $info.Add(' NOTES:')
        foreach ($n in $notes) { $info.Add('   ' + $n) }
    }
    $info.Add('')
    $info.Add('=' * 70)
    $info.Add(' BEFORE USING THIS IN PRODUCTION - acceptance test:')
    $info.Add('=' * 70)
    $info.Add(("   Import-GPO -BackupId '{0}' -Path '{1}' ``" -f $gpoGuid, $root))
    $info.Add("              -TargetName 'TEST Delta' -CreateIfNeeded")
    $info.Add("   Get-GPOReport -Name 'TEST Delta' -ReportType Html -Path .\test.html")
    $info.Add('')
    $info.Add(' Open test.html and confirm EVERY expected setting is present.')
    $info.Add(' Cross-check against the reference produced by:')
    $info.Add(("   .\ApplyBaselinev2.ps1 -Export -All -Baseline {0} -Mode {1}" -f $PkgName, $ModeKey))
    $info.Add(' A wrong Backup.xml does NOT raise an error - it silently drops settings.')
    Write-PlainText (Join-Path $root 'BUILD-INFO.txt') $info.ToArray()

    $bad = @($checks | Where-Object { $_ -match 'MISMATCH|failed' }).Count -gt 0
    return [pscustomobject]@{
        Package = $PkgName; Mode = $ModeKey; GpoName = $GpoName
        Root = $root; Guid = $gpoGuid; HasProblem = $bad
    }
}

# ============================================================
# 7. Main
# ============================================================
$packages = @(Get-BaselinePackages)
if ($packages.Count -eq 0) {
    Write-Host "[ERROR] No baseline package folders found under baseline_template\ or deltas\" -ForegroundColor Red
    exit 1
}

if ($List) {
    Write-Host "======================================================================"
    Write-Host " DELTA FILES PER PACKAGE / DOMAIN MODE"
    Write-Host "======================================================================"
    foreach ($p in $packages) {
        Write-Host ""
        Write-Host (" {0}" -f $p) -ForegroundColor Cyan
        foreach ($m in $DomainModes) {
            $d = @(Get-DeltaFiles $p $m)
            if ($d.Count -eq 0) {
                Write-Host ("   {0,-15} (no deltas)" -f $m) -ForegroundColor DarkGray
            } else {
                Write-Host ("   {0,-15} {1} file(s)" -f $m, $d.Count) -ForegroundColor Green
                foreach ($f in $d) { Write-Host ("       [{0}] {1}" -f $f.Layer, $f.Display) -ForegroundColor DarkCyan }
            }
        }
    }
    Write-Host ""
    Write-Host "Modes *-nondomain are not listed: a domain GPO only reaches domain-joined machines."
    exit 0
}

if (-not (Test-Path -LiteralPath $LgpoExe)) {
    Write-Host "[ERROR] LGPO.exe not found at: $LgpoExe" -ForegroundColor Red
    Write-Host "        It builds registry.pol; this script will not hand-write that format." -ForegroundColor Red
    exit 1
}

$ExportDir = if ($OutDir) {
    if ([IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $ScriptRoot $OutDir }
} else {
    Join-Path $ScriptRoot 'exports\gpo'
}
New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

# --- chon cac cap (goi, mode) ---
$pairs = New-Object System.Collections.Generic.List[object]
if ($All) {
    foreach ($p in $packages) {
        if ($Baseline -and $p -ne $Baseline) { continue }
        foreach ($m in $DomainModes) {
            if ($Mode -and $m -ne $Mode) { continue }
            if (@(Get-DeltaFiles $p $m).Count -eq 0) { continue }
            $pairs.Add([pscustomobject]@{ Pkg = $p; Mode = $m })
        }
    }
    if ($pairs.Count -eq 0) {
        Write-Host "[ERROR] No package/mode combination with delta files matched." -ForegroundColor Red
        Write-Host "        Run with -List to see what is available." -ForegroundColor Red
        exit 1
    }
} else {
    $pkg = $Baseline
    if (-not $pkg) {
        $pkg = $packages[(Select-FromList -Title "Baseline package:" -Items $packages)]
    } elseif ($packages -notcontains $pkg) {
        Write-Host "[ERROR] Package '$pkg' not found. Available: $($packages -join ', ')" -ForegroundColor Red
        exit 1
    }
    $md = $Mode
    if (-not $md) {
        $items = @($DomainModes | ForEach-Object {
            '{0,-15} {1} delta file(s)' -f $_, @(Get-DeltaFiles $pkg $_).Count })
        $md = $DomainModes[(Select-FromList -Title "Role / mode (domain-joined only):" -Items $items)]
    }
    $pairs.Add([pscustomobject]@{ Pkg = $pkg; Mode = $md })
}

Write-Host ""
Write-Host "======================================================================"
Write-Host " BUILD DELTA GPO BACKUP (importable into a domain GPO)"
Write-Host "======================================================================"
Write-Host ("  output folder = {0}" -f $ExportDir)
Write-Host  "  registry.pol  = built by LGPO.exe /r /w, then verified with /parse"
Write-Host  "  nothing on this machine is read or changed"

$results = New-Object System.Collections.Generic.List[object]
foreach ($pair in $pairs) {
    $gpoName = if ($Name -and $pairs.Count -eq 1) { $Name }
               else { 'ORG Delta - {0} {1}' -f $pair.Pkg, $pair.Mode }
    $r = New-DeltaGpoBackup -PkgName $pair.Pkg -ModeKey $pair.Mode -GpoName $gpoName -Dir $ExportDir
    if ($r) { $results.Add($r) }
}

Write-Host ""
Write-Host "======================================================================"
Write-Host (" DONE - built {0} delta GPO backup(s)" -f $results.Count)
Write-Host "======================================================================"
foreach ($r in $results) {
    $flag = if ($r.HasProblem) { '  [SELF-CHECK PROBLEM - read BUILD-INFO.txt]' } else { '' }
    Write-Host ("  {0}  ->  {1}{2}" -f $r.GpoName, $r.Root, $flag) -ForegroundColor $(if ($r.HasProblem) { 'Red' } else { 'Gray' })
}

if ($results.Count -gt 0) {
    Write-Host ""
    Write-Host "NEXT STEPS" -ForegroundColor Cyan
    Write-Host "  1. Import the Microsoft baseline GPOs (once per package):"
    Write-Host "       cd baseline_template\<package>\Scripts ; .\Baseline-ADImport.ps1"
    Write-Host "  2. ACCEPTANCE TEST each delta GPO in a test domain / throwaway GPO first:"
    foreach ($r in $results) {
        Write-Host ("       Import-GPO -BackupId '{0}' -Path '{1}' -TargetName 'TEST Delta' -CreateIfNeeded" -f $r.Guid, $r.Root)
    }
    Write-Host "       Get-GPOReport -Name 'TEST Delta' -ReportType Html -Path .\test.html"
    Write-Host "     Confirm EVERY expected setting appears, cross-checked against"
    Write-Host "     .\ApplyBaselinev2.ps1 -Export  output. A bad Backup.xml does NOT"
    Write-Host "     error - it silently drops settings." -ForegroundColor Yellow
    Write-Host "  3. Link the delta GPO with Link Order 1 (highest precedence) so it"
    Write-Host "     overrides the baseline GPOs, matching the local apply order."
}

if (@($results | Where-Object { $_.HasProblem }).Count -gt 0) { exit 1 }
exit 0
