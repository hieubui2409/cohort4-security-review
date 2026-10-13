# Quyết định của người dùng (USER-DECISIONS)

> Ghi lại các quyết định đã confirm với người quản lý (mentor) để không hỏi lại. Cập nhật: 2026-10-13.

## Bối cảnh & uỷ quyền
- Người dùng là **mentor/quản lý** của 8 nhóm trong org `AI20K-Build-Phase-Cohort-4`, uỷ quyền rà soát bảo mật source code + hệ thống deploy của chính các nhóm này.
- Mục tiêu: tìm **lỗ hổng** (hệ thống, code, tính năng), **đặc biệt phần agentic**: prompt injection, context management, context overflow, permission leak, và mọi lỗ hổng khác — để các nhóm hoàn thiện project.
- **Không** test tính năng (chức năng chạy đúng hay không). Chỉ tập trung bảo mật.
- Ngôn ngữ báo cáo: tiếng Việt.

## Quy ước
- `T` = team (nhóm), `P` = project. Theo quyết định: **đặt tên folder report trùng số P** (reviews/P-010, P-047, ...). Không cần mapping riêng.
- Báo cáo lưu theo từng nhóm: `./reviews/P-xxx/{evidences,scripts,README.md}`.

## Quy tắc chọn phương pháp chấm (chốt)
1. Lấy **link deploy online trong handoff** trước; không có thì **tìm trong repo (code/docs)**; không có link ở đâu cả thì **scan code**.
2. Nhóm **có deploy online VÀ đăng nhập được (tìm được tài khoản)** → chấm **cả hai**: test động qua **API** + scan code.
3. Tài khoản/credentials lấy từ **file trong handoff/repo**. Nếu thiếu → đã thống nhất fallback: **thử đăng nhập vài lần, không được thì scan code và ghi rõ** (không chặn chờ hỏi).
4. **Test bằng API, không test trên giao diện.** Dùng Claude-in-Chrome chỉ để đăng nhập/lấy token khi cần; đọc source để suy ra API.

## Phạm vi can thiệp trên hệ thống LIVE
- **Đã chọn: "Thử đầy đủ (gồm thay đổi dữ liệu)."**
- Cho phép tạo/sửa/xoá bản ghi test, thử rate-limit, gọi AI nhiều lần để kiểm tra context overflow.
- Nguyên tắc tự áp dụng để giảm rủi ro (không mâu thuẫn với quyết định trên): ưu tiên tạo dữ liệu test mang nhãn rõ ràng; tránh xoá dữ liệu thật của người khác khi không cần cho PoC; mọi hành vi đều ghi log vào evidences.

## Giới hạn kỹ thuật môi trường
- SSH cổng 22 tới GitHub bị chặn; git config global rewrite `git@github.com:` → HTTPS.
- Scan code: **tối đa 2 subagent**, bám đúng scope ở trên, không review tràn lan/ngoài scope.

## HANDOFF THẬT: ./handoff có 5 folder (= 5 nhóm có deploy)
Handoff nằm ở `./handoff/{T-047,T-075,T-123,T-136,T-145}`. T-xxx = P-xxx (cùng số). Đây là 5 nhóm **chấm động qua API**. 3 nhóm còn lại (P-010, P-140, P-143) không có handoff → **scan code** (P-010 có link vercel trong repo nên dò thêm nếu kịp).

## Tình trạng deploy & credentials (kiểm tra 2026-10-13)
| Project | Nguồn link | Link deploy | HTTP | Tài khoản | Hướng xử lý |
|---|---|---|---|---|---|
| P-047 | handoff T-047 | https://<REDACTED_DEPLOY>/ | 200 | cư dân `user`/`<REDACTED_PASSWORD>`; BQL `admin`/`admin1234` | API + scan |
| P-075 | handoff T-075 | https://<REDACTED_DEPLOY> | 302 | <REDACTED_EMAIL>, <REDACTED_EMAIL>, <REDACTED_EMAIL>, <REDACTED_EMAIL> (mật khẩu trong demo-credentials.json) | API + scan |
| P-123 | handoff T-123 | https://<REDACTED_DEPLOY> | cold-start (Render) | customer01/`Customer@123456`, driver01/`Driver@123456`, cskh01/`CSKH@12345678` | API (chờ wake) + scan |
| P-136 | handoff T-136 | http://<REDACTED_DEPLOY>/login (backend IP <REDACTED_IP>:8000, MinIO :9000) | 301 | admin/`Admin@123`, manager/`Manager@123`, driver1/`Driver@123` | API + scan |
| P-145 | handoff T-145 | https://<REDACTED_DEPLOY>/ | 307 | HR `<REDACTED_EMAIL>`/`<REDACTED_PASSWORD>` | API + scan |
| P-010 | repo (không có handoff) | https://<REDACTED_DEPLOY> | 200 | chưa có | scan code (dò login nếu kịp) |
| P-140 | — | (không có) | — | — | scan code |
| P-143 | — | (không có) | — | — | scan code |

## Trọng tâm lỗ hổng cần tìm
1. **Agentic**: prompt injection (trực tiếp + gián tiếp qua tài liệu/ảnh người dùng upload — RAG), context management, context overflow (nhồi context làm lộ/又 bỏ qua system prompt), **permission leak** (agent/endpoint chạy quyền cao hơn user).
2. **Phân quyền / IDOR**: user A đọc/sửa dữ liệu user B; vai trò thấp gọi endpoint vai trò cao.
3. Auth (JWT yếu, secret lộ, reset/đổi mật khẩu), injection (SQL/NoSQL/command), SSRF/file upload, secret lộ trong repo, rate-limit/chi phí AI.

## 2026-10-13 — Repo public cho findings (redacted)
- **Sở hữu:** tài khoản GitHub cá nhân (hieubt15), KHÔNG đặt trong org cohort.
- **Tên repo:** `cohort4-security-review` (public).
- **Nội dung:** README tổng hợp (redacted) + `security-report.html` + READMEs từng nhóm (redacted) + **scripts PoC (redacted mạnh)**.
- **Mức redaction (MẠNH):** xoá mật khẩu/token/JWT secret/MinIO creds/IP/URL deploy/PII + **payload khai thác hoạt động** (mô tả thay vì tái hiện nguyên văn); GIỮ mô tả lỗ hổng + CWE/OWASP + input-output đã che.
- **Thời điểm:** tạo & push SAU KHI hoàn tất các test động đang chạy (P-145 e2e + subagent P-143/P-140/P-010 local).

## 2026-10-13 — Chốt mục "phán quyết model thật dưới injection"
- Mentor **CHẤP NHẬN là giới hạn đã ghi nhận**: độ nhạy nội tại của model proprietary dưới injection cho **P-075** (VLM chạy `mock`) và **P-143** (OpenRouter URL hard-code HTTPS, không có key) KHÔNG đo được vì cần API key trả phí ở staging — ngoài tầm của reviewer.
- Đã kiểm đầy đủ: toàn bộ **tầng phòng thủ QUANH model** cho mọi nhóm (whitelist strip, grounding "references are data", taint-filter, screen chunk, ngưỡng similarity, gate chủ đề biến động).
- **P-123**: model Gemini thật ĐÃ quan sát được (chuẩn hoá khiếu nại, không lộ system prompt) → không còn là gap.
- Review **coi như HOÀN TẤT** trong phạm vi được cấp phép + khôi phục được.
