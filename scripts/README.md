# scripts\ — script remediation

Các thay đổi **không** biểu diễn được bằng Group Policy đặt ở đây. Những gì biểu diễn được bằng policy thì thuộc `deltas\` (xem [deltas/README.md](../deltas/README.md)) để `ApplyBaselinev2.ps1` áp cùng baseline và đưa vào `delta_report`.

| Việc cần làm | Đặt ở đâu |
|---|---|
| Registry policy, User Rights, Security Options, Advanced Audit | `deltas\` |
| Đổi tên / disable tài khoản, cài agent, cấu hình service, tác vụ một lần | `scripts\` |

## Quy ước

- Một script = một việc. Tên theo dạng `Verb-Noun.ps1` (động từ chuẩn của PowerShell).
- `#Requires -Version 5.1` ở dòng đầu.
- `[CmdletBinding(SupportsShouldProcess = $true)]` để có `-WhatIf` — **luôn chạy `-WhatIf` trước** trên máy thật.
- **Idempotent**: chạy lần 2 không được lỗi và không được đổi gì thêm.
- Tự kiểm tra quyền Administrator, và tự từ chối nếu chạy sai loại máy (ví dụ domain controller).
- Đọc lại trạng thái từ hệ thống để **xác nhận** sau khi thay đổi, đừng tin giá trị trả về.
- Exit code: `0` = đúng trạng thái mong muốn (vừa sửa xong, hoặc vốn đã đúng), `1` = lỗi.

## Danh sách script

| Script | Việc |
|---|---|
| `Rename-LocalAdministrator.ps1` | Đổi tên tài khoản Administrator nội bộ (tìm theo RID 500) |

### Rename-LocalAdministrator.ps1

```powershell
.\Rename-LocalAdministrator.ps1 -NewName beta_admin -WhatIf   # xem trước, không đổi gì
.\Rename-LocalAdministrator.ps1 -NewName beta_admin           # có hỏi xác nhận
.\Rename-LocalAdministrator.ps1 -NewName beta_admin -Confirm:$false   # không hỏi (dùng cho automation)
```

Script có `ConfirmImpact = 'High'` nên **mặc định sẽ hỏi xác nhận**; dùng `-Confirm:$false` khi chạy tự động.

Tìm tài khoản theo **SID kết thúc bằng `-500`**, không theo tên `"Administrator"`, vì tên phụ thuộc ngôn ngữ Windows (`Administrateur`, `Administrador`…) và có thể đã bị đổi từ trước. RID 500 thì không bao giờ đổi.

Không chạy được trên **domain controller**: DC không có SAM nội bộ, `Administrator` ở đó là tài khoản của domain — phải đổi bằng công cụ AD / GPO domain.

> **Đổi tên KHÔNG làm đổi SID.** ACL trên file/registry, User Rights (URA) và group membership đều lưu theo SID nên giữ nguyên hiệu lực. **Không cần** gán lại quyền gì sau khi đổi tên.
>
> Cụ thể, **đừng** làm kiểu này:
>
> ```powershell
> # SAI - ghi đè TOÀN BỘ danh sách quyền bằng đúng 1 SID
> (Get-Content $inf) -replace '^SeShutdownPrivilege\s*=.*', "SeShutdownPrivilege = *$sid" | Set-Content $inf
> secedit /configure /db ... /areas USER_RIGHTS
> ```
>
> Dòng `-replace` thay cả dòng, nên `Administrators` và `Backup Operators` bị **mất** quyền shutdown. Baseline của Microsoft không cấu hình `SeShutdownPrivilege`, nên đây là ghi đè lên mặc định của OS. Nếu thật sự cần sửa một User Right, hãy viết nó vào file `.inf` trong `deltas\` với **đầy đủ** SID muốn giữ, ví dụ:
>
> ```inf
> [Privilege Rights]
> SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551
> ```

## Vị trí trong quy trình audit

`ApplyBaselinev2.ps1` **không** tự chạy các script trong thư mục này. Chúng là bước "Xử lý các lỗi tìm thấy" (Bước 2 trong [README](../README.md)) giữa lần chạy đầu và `-Recheck`.
