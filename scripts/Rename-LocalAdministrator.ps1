#Requires -Version 5.1
<#
    Rename-LocalAdministrator.ps1
    -----------------------------
    Doi ten tai khoan Administrator NOI BO (built-in), tim theo SID ket thuc
    bang "-500".

    Vi sao tim theo SID chu khong theo ten "Administrator":
      - Ten tai khoan phu thuoc ngon ngu Windows: Administrateur (fr),
        Administrador (es), Administrator (en)...
      - Tai khoan co the DA bi doi ten tu truoc (lan chay truoc, hoac policy)
        -> Rename-LocalUser -Name "Administrator" se bao loi "not found".
      - RID 500 cua built-in administrator thi KHONG BAO GIO doi.

    QUAN TRONG: doi ten KHONG lam doi SID. Moi ACL tren file/registry, moi
    user right (URA) va moi group membership deu luu theo SID, nen chung giu
    nguyen hieu luc sau khi doi ten. KHONG can cau hinh lai quyen gi ca.
    (Dung dung secedit de "gan lai" quyen sau khi doi ten: viec do khong can
    thiet va de ghi de ca danh sach quyen - xem scripts\README.md.)

    KHONG chay tren domain controller: DC khong co SAM noi bo, tai khoan
    "Administrator" tren DC la tai khoan CUA DOMAIN (tai khoan dac quyen nhat
    cua rung AD). Doi ten no phai lam bang cong cu AD / GPO domain.

    LUU Y VE AN NINH: doi ten chi la che giau (security by obscurity). SID
    co RID 500 van co the liet ke duoc tu xa. Nen ket hop:
      - disable tai khoan built-in administrator
      - "Deny access to this computer from the network" / "Deny log on
        through Remote Desktop Services" cho local account (xem deltas\)

    Exit code:
      0 = tai khoan dang co dung ten mong muon (vua doi xong, hoac von da dung)
      1 = loi, khong doi duoc

    Vi du:
        .\Rename-LocalAdministrator.ps1 -NewName beta_admin -WhatIf
        .\Rename-LocalAdministrator.ps1 -NewName beta_admin
        .\Rename-LocalAdministrator.ps1            # dung ten mac dinh beta_admin
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$NewName = 'beta_admin'
)

$ErrorActionPreference = 'Stop'

Write-Host "======================================================================"
Write-Host " RENAME BUILT-IN LOCAL ADMINISTRATOR"
Write-Host "======================================================================"

# ============================================================
# 1. Phai chay bang quyen Administrator
# ============================================================
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# ============================================================
# 2. Tu choi chay tren domain controller
#    Win32_OperatingSystem.ProductType: 1 = workstation, 2 = DC, 3 = server
# ============================================================
$os = Get-CimInstance -ClassName Win32_OperatingSystem
if ([int]$os.ProductType -eq 2) {
    Write-Host "[ERROR] This machine is a domain controller." -ForegroundColor Red
    Write-Host "        A DC has no local SAM - 'Administrator' there is the DOMAIN account," -ForegroundColor Red
    Write-Host "        the most privileged account in the forest. Renaming it locally is not" -ForegroundColor Red
    Write-Host "        supported. Use Active Directory tools or a domain GPO instead." -ForegroundColor Red
    exit 1
}

# ============================================================
# 3. Kiem tra ten moi co hop le voi SAM khong
#    - toi da 20 ky tu
#    - khong duoc chua: " / \ [ ] : ; | = , + * ? < >
#    - khong duoc toan dau cach / dau cham, khong ket thuc bang dau cham
# ============================================================
$NewName = $NewName.Trim()
$invalidSamChars = '["/\\\[\]:;|=,+*?<>]'

if ([string]::IsNullOrWhiteSpace($NewName)) {
    Write-Host "[ERROR] -NewName must not be empty." -ForegroundColor Red
    exit 1
}
if ($NewName.Length -gt 20) {
    Write-Host ("[ERROR] -NewName '{0}' is {1} characters; a SAM account name allows at most 20." -f `
        $NewName, $NewName.Length) -ForegroundColor Red
    exit 1
}
if ($NewName -match $invalidSamChars) {
    Write-Host ("[ERROR] -NewName '{0}' contains a character that SAM does not allow." -f $NewName) -ForegroundColor Red
    Write-Host '        Not allowed: " / \ [ ] : ; | = , + * ? < >' -ForegroundColor Red
    exit 1
}
if ($NewName -match '^[\s.]+$' -or $NewName.EndsWith('.')) {
    Write-Host ("[ERROR] -NewName '{0}' may not consist only of dots/spaces nor end with a dot." -f $NewName) -ForegroundColor Red
    exit 1
}

# ============================================================
# 4. Tim built-in administrator theo RID 500
#    Dung CIM thay vi "Get-LocalUser" khong tham so: Get-LocalUser co the
#    bao loi "Failed to compare two elements in the array" tren may co SID
#    mo coi. Loc them Domain = <ten may> cho nhanh tren may join domain.
# ============================================================
$localFilter = "LocalAccount = TRUE AND Domain = '{0}'" -f $env:COMPUTERNAME

$adminAccounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter $localFilter |
                   Where-Object { $_.SID -like '*-500' })

if ($adminAccounts.Count -ne 1) {
    Write-Host ("[ERROR] Expected exactly one built-in administrator (SID ending in -500), found {0}." -f `
        $adminAccounts.Count) -ForegroundColor Red
    exit 1
}
$admin = $adminAccounts[0]

Write-Host ("  current name = {0}" -f $admin.Name)
Write-Host ("  SID          = {0}" -f $admin.SID)
Write-Host ("  disabled     = {0}" -f $admin.Disabled)
Write-Host ("  target name  = {0}" -f $NewName)
Write-Host ""

# ============================================================
# 5. Idempotent: da dung ten thi khong lam gi
#    (so sanh -eq cua PowerShell khong phan biet hoa thuong, giong SAM)
# ============================================================
if ($admin.Name -eq $NewName) {
    Write-Host ("[OK] The built-in administrator is already named '{0}' - nothing to do." -f $NewName) -ForegroundColor Green
    exit 0
}

# ============================================================
# 6. Ten moi da bi tai khoan / nhom khac dung chua?
#    User va group dung CHUNG namespace trong SAM -> phai kiem tra ca hai.
#    Query 2 class cu the (Win32_UserAccount, Win32_Group) thay vi class cha
#    Win32_Account: query Win32_Account phai duyet nhieu provider va co the
#    rat cham tren mot so may.
# ============================================================
$clash = @(
    foreach ($cls in @('Win32_UserAccount', 'Win32_Group')) {
        Get-CimInstance -ClassName $cls -Filter $localFilter |
            Where-Object { $_.Name -eq $NewName -and $_.SID -ne $admin.SID }
    }
)
if ($clash.Count -gt 0) {
    Write-Host ("[ERROR] The name '{0}' is already taken by a local account or group (SID {1})." -f `
        $NewName, $clash[0].SID) -ForegroundColor Red
    Write-Host "        Pick another name, or remove/rename that object first." -ForegroundColor Red
    exit 1
}

# ============================================================
# 7. Doi ten
#    Dung -SID (khong dung -Name) de khong phu thuoc ten hien tai / ngon ngu.
# ============================================================
if (-not (Get-Command -Name 'Rename-LocalUser' -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Cmdlet Rename-LocalUser is not available on this system." -ForegroundColor Red
    Write-Host "        It ships with the Microsoft.PowerShell.LocalAccounts module" -ForegroundColor Red
    Write-Host "        (Windows 10 / Server 2016 and later, 64-bit PowerShell)." -ForegroundColor Red
    exit 1
}

$target = ("built-in local administrator '{0}' (SID {1})" -f $admin.Name, $admin.SID)
if (-not $PSCmdlet.ShouldProcess($target, ("Rename to '{0}'" -f $NewName))) {
    Write-Host "==> -WhatIf / declined: nothing was changed." -ForegroundColor DarkGray
    exit 0
}

try {
    Rename-LocalUser -SID ([System.Security.Principal.SecurityIdentifier]$admin.SID) -NewName $NewName
} catch {
    Write-Host ("[ERROR] Rename failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# ============================================================
# 8. Doc lai tu he thong de xac nhan (khong tin ket qua tra ve)
# ============================================================
$after = @(Get-CimInstance -ClassName Win32_UserAccount -Filter $localFilter |
           Where-Object { $_.SID -like '*-500' })

if ($after.Count -eq 1 -and $after[0].Name -eq $NewName) {
    Write-Host ("[OK] Renamed '{0}' -> '{1}'" -f $admin.Name, $after[0].Name) -ForegroundColor Green
    Write-Host ("     SID unchanged: {0}" -f $after[0].SID) -ForegroundColor Green
    Write-Host ""
    Write-Host "     ACLs, user rights and group memberships are stored by SID," -ForegroundColor DarkGray
    Write-Host "     so none of them need to be reconfigured." -ForegroundColor DarkGray
    exit 0
}

$nameNow = if ($after.Count -eq 1) { $after[0].Name } else { '(not found)' }
Write-Host ("[ERROR] Verification failed - the RID 500 account is now named '{0}'." -f $nameNow) -ForegroundColor Red
exit 1
