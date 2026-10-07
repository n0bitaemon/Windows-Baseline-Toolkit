# Windows Baseline Audit Toolkit

Công cụ audit security baseline cho máy Windows. Script thực hiện:

1. Chụp lại cấu hình Group Policy (GPO) hiện tại của máy ra file `.PolicyRules` và chạy remediate.
2. Kiểm tra các công cụ bảo mật bắt buộc có được cài và cấu hình đúng không: **MDE, Wazuh agent, Sysmon, ghi log lệnh/PowerShell**.
3. (Tùy chọn) tự động áp baseline bảo mật (GPO mẫu) vào máy bằng LGPO.

Có 2 phiên bản script:

| Script | Baseline lấy từ đâu |
|---|---|
| `ApplyBaselinev2.ps1` (**khuyến nghị**) | Tự đọc gói Microsoft Security Baseline trong `baseline_template\` và tự nhận các mode (client domain-joined / non-domain, server member / non-domain / DC). Cấu hình riêng của tổ chức đặt trong `deltas\`. **Không** cần dựng sẵn file `.PolicyRules` cho từng role. |
| `Apply-Baseline.ps1` (cũ) | Chọn một file `.PolicyRules` dựng sẵn trong `policy_rules\` |

Hai script có cùng quy trình (lần đầu → tự sửa → `--recheck`) và cùng định dạng file kết quả. Phần dưới mô tả `Apply-Baseline.ps1`; các điểm khác của v2 nằm ở mục [ApplyBaselinev2.ps1](#applybaselinev2ps1).

## Quy trình audit đầy đủ

Một lượt audit thường gồm 3 bước: **chạy lần đầu → tự sửa các lỗi tìm thấy → chạy lại để xác nhận (recheck)**.

### Bước 1 — Chạy audit lần đầu

```powershell
.\Apply-Baseline.ps1
```

Script sẽ hỏi lần lượt:

- Mã nhân viên
- IP của máy
- Chọn 1 file baseline `.PolicyRules` trong `policy_rules\` (dùng nếu muốn áp ở bước 3)

Sau đó tự động chạy, không cần thao tác gì thêm ngoài xác nhận:

| Bước | Việc làm | Kết quả |
|---|---|---|
| [1] SNAPSHOT | Chụp cấu hình GPO hiện tại của máy | `pre_<BASE>.PolicyRules` |
| [2] CHECK | Kiểm tra MDE / Wazuh / Sysmon / ghi log | `pre_scriptcheck_<BASE>.txt` |
| [3] REMEDIATE | Hỏi **y/N** — nếu chọn `y`, áp dụng baseline đã chọn bằng LGPO | `lgpo.out` (thành công) + `lgpo.err` (lỗi nếu có) |

Toàn bộ kết quả nằm trong folder mới tạo: `audit_<hostname>_<ip>_<timestamp>_<mã nhân viên>\`.

### Bước 2 — Xử lý các lỗi tìm thấy

Mở file `pre_scriptcheck_<BASE>.txt`, tìm các dòng `FAIL` để biết các cấu hình chưa đáp ứng tiêu chuẩn baseline. Ví dụ thường gặp:

- Chưa onboard MDE, hoặc real-time protection / tamper protection đang tắt.
- Chưa cài Wazuh agent, hoặc Wazuh chưa trỏ đúng manager / chưa thu thập đúng log.
- Chưa cài Sysmon, hoặc Sysmon đang bật nhưng thiếu ghi log một số sự kiện.
- Chưa bật audit ghi log tạo tiến trình (process creation) hoặc PowerShell logging.

### Bước 3 — Chạy lại để xác nhận (recheck)

Sau khi đã sửa xong, chạy lại với cờ `--recheck` (hoặc `-Recheck`):

```powershell
.\Apply-Baseline.ps1 --recheck
```

- Script liệt kê các folder `audit_*` đã tạo trước đó — chọn đúng folder vừa audit ở Bước 1.
- Sinh 2 file mới **trong đúng folder cũ**: `post_<BASE>.PolicyRules`, `post_scriptcheck_<BASE>.txt`. Nếu chạy `--recheck` nhiều lần, 2 file này sẽ bị ghi đè bằng kết quả mới nhất.

## Giải thích các file kết quả

| File | Ý nghĩa |
|---|---|
| `pre_<BASE>.PolicyRules` | Snapshot cấu hình GPO **trước** khi áp baseline |
| `pre_scriptcheck_<BASE>.txt` | Kết quả kiểm tra MDE/Wazuh/Sysmon/ghi log **trước** khi sửa |
| `post_<BASE>.PolicyRules` | Snapshot cấu hình GPO sau khi recheck |
| `post_scriptcheck_<BASE>.txt` | Kết quả kiểm tra security stack sau khi recheck |
| `lgpo.out` | Log các setting LGPO áp thành công (chỉ có nếu chọn remediate ở Bước 1) |
| `lgpo.err` | Log lỗi khi áp LGPO, nếu có |

Nếu chỉ chạy audit mà không remediate và không recheck, folder chỉ có 2 file `pre_*`.

Muốn so sánh trước/sau, mở **Policy Analyzer** (`PolicyAnalyzer\PolicyAnalyzer.exe`) → Add cả 2 file `.PolicyRules` → View/Compare.

Trong file `.txt`, mỗi dòng kiểm tra có 1 trong 4 trạng thái:

- **PASS** — đạt
- **FAIL** — chưa đạt, cần xử lý
- **WARN** — đạt một phần, cần lưu ý thêm
- **SKIP** — không áp dụng hoặc không kiểm tra được

Cuối file có phần **TỔNG KẾT** (`SUMMARY`) đếm số lượng từng loại và liệt kê lại toàn bộ mục `FAIL` để dễ tra cứu nhanh.

## ApplyBaselinev2.ps1

```powershell
.\ApplyBaselinev2.ps1 -List          # xem gói / mode / GPO / delta mà script nhận ra (không thay đổi gì, không cần admin)
.\ApplyBaselinev2.ps1                # audit lần đầu
.\ApplyBaselinev2.ps1 --recheck      # xác nhận sau khi sửa
# Chạy không cần menu:
.\ApplyBaselinev2.ps1 -Baseline "Windows Server-2022-Security-Baseline" -Mode server-nondomain -Exclude 'Credential Guard'
```

**Chọn gói và mode.** Script quét `baseline_template\` và đọc tên GPO trong `Backup.xml`, từ đó suy ra mode theo quy ước đặt tên của Microsoft:

| Mode | GPO được áp |
|---|---|
| `client-domain` / `client-nondomain` | Toàn bộ GPO của gói client |
| `server-member` / `server-nondomain` | GPO server, **trừ** GPO có tên chứa `Domain Controller` |
| `server-dc` | GPO server, **trừ** GPO có tên chứa `Member Server` |

Kết quả trùng với `Baseline-LocalInstall.ps1` của Microsoft. Script tự **gợi ý** gói khớp với OS của máy và mode khớp với vai trò (`DomainRole`) của máy. Nếu bạn chọn khác gợi ý, script cảnh báo và hỏi xác nhận. Khi được hỏi, có thể bỏ bớt GPO bằng từ khoá (ví dụ `Credential Guard`, `BitLocker`). Với gói đặt tên khác thường, thêm file `baseline.psd1` vào thư mục gói để khai báo tay:

```powershell
@{ Modes = @{ 'server-member' = @('MSFT ... - Member Server', 'MSFT ... - Domain Security'); ... } }
```

**Delta.** Các cấu hình khác baseline đặt trong `deltas\` (xem [deltas/README.md](deltas/README.md)). Script áp chúng **sau** GPO của Microsoft. Với mode `*-nondomain`, script tự áp thêm `DeltaForNonDomainJoined` có sẵn trong gói Microsoft. Khi có baseline mới: chép gói vào `baseline_template\`, chạy `-List`, rồi audit như bình thường. Delta cũ được dùng tiếp.

**Remediate.** Tương tự script của Microsoft: `LGPO /e …` (client side extensions) → `LGPO /g` từng GPO → các delta (`/t`, `/s`, `/a`) → `gpupdate /force`. Trên **domain controller** script không remediate (Microsoft cũng chặn việc này). DC cần được import GPO qua AD.

**File kết quả thêm so với bản cũ** (chỉ tạo ở lần chạy đầu):

| File | Ý nghĩa |
|---|---|
| `baseline_<BASE>.PolicyRules` | Baseline tham chiếu = GPO của mode đã chọn + delta, không có conflict. Mở cùng `pre_*` / `post_*` trong Policy Analyzer để so sánh |
| `delta_report_<BASE>.txt` | Từng mục delta so với baseline: `OVERRIDE` / `REMOVE` / `NEW` / `REDUNDANT` / `INFO` / `ERROR` |

Report `*_scriptcheck_*.txt` có thêm 2 dòng header là `Baseline` và `Mode`. Thư mục `policy_rules\` không còn cần cho v2.

## Lưu trữ

Nén và lưu trữ folder output `audit_<BASE>/` để phục vụ hậu kiểm.
