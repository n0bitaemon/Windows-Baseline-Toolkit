# Windows Baseline Audit Toolkit

Công cụ audit security baseline cho máy Windows. Script thực hiện:

1. Chụp lại cấu hình Group Policy (GPO) hiện tại của máy ra file `.PolicyRules` và chạy remediate.
2. Kiểm tra các công cụ bảo mật bắt buộc có được cài và cấu hình đúng không: **MDE, Wazuh agent, Sysmon, ghi log lệnh/PowerShell**.
3. (Tùy chọn) tự động áp baseline bảo mật (GPO mẫu) vào máy bằng LGPO.

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

## Lưu trữ

Nén và lưu trữ folder output `audit_<BASE>/` để phục vụ hậu kiểm.
