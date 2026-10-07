# deltas\ — cấu hình riêng của tổ chức so với Microsoft Security Baseline

`ApplyBaselinev2.ps1` áp các GPO của Microsoft trước, **sau đó** áp các file trong thư mục này. File áp sau sẽ ghi đè file áp trước. Baseline gốc trong `baseline_template\` không bao giờ bị sửa.

## Thứ tự áp

| # | Thư mục | Áp cho |
|---|---|---|
| 1 | `<gói baseline>\Scripts\ConfigFiles\DeltaForNonDomainJoined.*` | Mode `*-nondomain`, file có sẵn trong gói của Microsoft |
| 2 | `deltas\common\` | Mọi mode, mọi gói |
| 3 | `deltas\<mode>\` | Một mode, áp cho mọi gói |
| 4 | `deltas\<tên thư mục gói>\common\` | Một gói, áp cho mọi mode |
| 5 | `deltas\<tên thư mục gói>\<mode>\` | Một gói và một mode |

Mode hợp lệ: `client-domain`, `client-nondomain`, `server-member`, `server-nondomain`, `server-dc`.
Trong mỗi thư mục, file được áp theo thứ tự tên. Nên đặt tiền tố số: `10-...`, `20-...`.
Tên thư mục gói phải trùng **chính xác** với tên thư mục trong `baseline_template\`.
Để kiểm tra thư mục nào bị gõ sai tên (sẽ không bao giờ được áp), chạy `.\ApplyBaselinev2.ps1 -List`.

## Định dạng file (theo phần mở rộng)

| Đuôi | Nội dung | Lệnh LGPO |
|---|---|---|
| `.txt` | LGPO text: registry policy, gồm Administrative Templates, MSS, SecGuide… | `LGPO /t` |
| `.inf` | Security template: User Rights, password/lockout, Security Options | `LGPO /s` |
| `.csv` | Advanced Audit Policy, cùng định dạng `audit.csv` của `auditpol /backup` | `LGPO /a` |

File có đuôi khác (`.md`, `.example`, …) bị bỏ qua. Xem mẫu trong `common\*.example`.

- **LGPO text:** mỗi mục gồm 4 dòng liên tiếp `Computer|User` / key / value / action. Action có thể là `DWORD:n`, `SZ:text`, …, `DELETE` (đưa về Not configured), `DELETEALLVALUES`, `CLEAR`. Cú pháp đầy đủ nằm trong `LGPO\LGPO.pdf`.
- **INF:** khi ghi một User Right, toàn bộ danh sách của quyền đó sẽ bị **thay thế**. Nên dùng SID (`*S-1-5-32-544`) thay vì tên nhóm, để báo cáo so sánh đúng với baseline.

## Mỗi lần chạy: delta_report_<BASE>.txt

Script so từng mục delta với baseline đã chọn và đánh trạng thái:

- `OVERRIDE`: delta đổi giá trị mà baseline đặt. Đây là trường hợp bình thường.
- `REMOVE`: delta đưa một setting của baseline về Not configured.
- `NEW`: baseline (phiên bản này) không cấu hình setting đó. Cần xem lại xem delta còn cần không.
- `REDUNDANT`: baseline đã có đúng giá trị này. Có thể xoá mục delta.
- `ERROR`: không đọc được file. Rất có thể LGPO cũng sẽ lỗi khi áp file này.

Khi Microsoft phát hành baseline mới, hãy chép gói vào `baseline_template\`, chạy `-List` để kiểm tra, rồi đọc `delta_report` ở lần audit đầu tiên. Các mục `NEW`/`REDUNDANT` là chỗ baseline mới đã thay đổi so với lúc bạn viết delta.

**Ghi lý do** cho mỗi mục bằng dòng comment `;` ngay phía trên mục đó. Delta chính là danh sách các điểm lệch so với baseline, cần được giải trình khi audit.
