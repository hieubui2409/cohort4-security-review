# Cohort 4 — Báo cáo rà soát bảo mật (bản công khai, đã redact)

> ⚠️ **Bản công khai đã REDACT MẠNH.** Đã loại: mật khẩu, token, JWT secret, credential MinIO, IP, hostname deploy, email/PII — thay bằng `<REDACTED_*>`. Thư mục `evidences/` (log/JSON/ảnh thô chứa token & PII) **không** đưa lên công khai; chỉ giữ nội bộ. Scripts PoC giữ kỹ thuật nhưng đã gỡ credential/target → **không chạy trực tiếp** được.
>
> 📊 **Báo cáo trực quan (artifact công khai):** https://claude.ai/artifact/RkBfcb3Nh9ow4MM7j9Gogw
>
> Rà soát được **mentor ủy quyền** trên chính dự án của 8 nhóm; môi trường test, dữ liệu do sinh viên tạo. Tấn công có kiểm soát + đảo ngược; bản ghi test gắn `SECTEST-` kèm cơ chế dọn. Review đã **hoàn tất trong phạm vi được cấp phép** (xem §7 + goal.md §9).

---

# BÁO CÁO TỔNG HỢP RÀ SOÁT BẢO MẬT — Cohort 4 (8 nhóm)

> Cho mentor/quản lý. Ngày: 2026-10-13. Phạm vi & quyết định: `USER-DECISIONS.md`. Quy tắc đầy đủ: `../goal.md`. Mẫu finding: `FINDING-TEMPLATE.md`.
> Mỗi nhóm có báo cáo riêng `reviews/P-xxx/README.md` + `evidences/` (bằng chứng) + `scripts/` (script tái hiện).

## 1. Cách làm
- **5 nhóm có handoff + đăng nhập được** (`./handoff/T-xxx`) → **test động qua API trên bản deploy** + đọc source: **P-047, P-075, P-123, P-136, P-145**.
- **3 nhóm không có deploy/handoff** → scan code tĩnh **+ DỰNG CHẠY LOCAL để test động** (docker compose / venv riêng, mock dịch vụ LLM, chạy từ ngoài repo `python -I`): **P-010, P-140, P-143** (mỗi project 1 subagent riêng). Đây là phần bổ sung so với quy tắc "chỉ scan" ban đầu, giúp phủ động cho cả nhóm không deploy.
- **P-145**: ngoài battery động, đã chạy **injection RAG đầu-cuối thật** (tạo employee qua intake → publish doc nhiễm độc → chat) — xem §2 + `P-145/README.md`.
- Trọng tâm: **agentic** (prompt injection trực tiếp + gián tiếp/stored, context overflow, permission leak, tool abuse), phân quyền/IDOR/BFLA, auth/secret, injection, default creds, rò rỉ dữ liệu.
- Tấn công có kiểm soát + đảo ngược; **không** cố ý gây outage hạ tầng hay xoá sạch DB (xem mục 5). Mọi bản ghi test gắn `SECTEST-` + có SQL/teardown dọn dẹp.

## 2. Bảng xếp hạng mức độ rủi ro (nặng → nhẹ)
| Hạng | Nhóm | Phương pháp | Critical | High | Medium | Low/Info | Điểm nổi bật |
|---|---|---|:--:|:--:|:--:|:--:|---|
| 🔴 1 | **P-136** | API động | **2** | **2** | 2 | + | Giả mạo JWT → chiếm ADMIN; MinIO default creds; ingestion không auth; BOLA; **race nhận ca (5 ca ACTIVE đồng thời)** |
| 🟠 2 | **P-010** | Scan + **động local** | 0 | **2** | **2** | 4 | **JWT forge XÁC NHẬN ĐỘNG → chiếm admin** `/admin/field-hosts`; commit Chrome profile (cookie+mật khẩu thật); **IDOR/BFLA an toàn động** (2 tenant+2 landlord); **FINDING-08 slot_taken giả** dưới tải ghi; FINDING-07 không trần token |
| 🟡 3 | **P-145** | API động + **e2e** | 0 | **1** | 2 | + | Mật khẩu khởi tạo dùng chung; detector injection bypass 9/9; thiếu rate-limit. **Chat RAG e2e injection: PASS (phòng thủ 5 tầng)** |
| 🟡 4 | **P-143** | Scan + **động local** | 0 | 0 | **3** | 5 | **Định vị lại (động):** FINDING-01 OCR là **code chết**; vector thật = **FINDING-09 injection đối soát** (Medium, giảm nhẹ mạnh: model chỉ chọn từ danh sách code-side, luôn có người duyệt); context overflow 40KB; rate-limit/lockout. Caching theo tenant = điểm cộng |
| 🟢 5 | **P-047** | API động | 0 | 0 | 1 | 2 | `/auth/reset` wipe-app không auth (chặn bằng mã tĩnh); battery PASS |
| 🟢 6 | **P-140** | Scan + **động local** | 0 | 0 | **1** | 2 | **Mới (động): `/api/v1/chat` không auth + không giới hạn body → DoS** (max_length áp sau khi parse 200MB); thiếu security headers |
| 🟢 7 | **P-123** | API động | 0 | 0 | **1** | 2 | Rate-limit login KHÔNG hiệu lực ở live (proxy IP); còn lại rất chắc |
| 🟢 8 | **P-075** | API động | 0 | 0 | 0 | 1 | Chỉ demo-login; nền tảng rất chắc |

> "+" = có thêm mục Low/Info/hardening; xem README từng nhóm. **P-140 không còn "sạch"** sau test động (có DoS Medium). **P-010 lên hạng** do JWT forge nay xác nhận động + gap bộ lọc mới.

## 3. Các lỗ hổng NGHIÊM TRỌNG cần sửa gấp
### P-136 (DriverGuard) — 2 CRITICAL đã tái hiện trên LIVE
1. **JWT secret hardcode** (`config.py`: `<REDACTED_JWT_SECRET>`, HS256) → mình **tự ký token ADMIN không cần đăng nhập** và gọi `/auth/me` thành công (HTTP 200), tạo được user ADMIN mới (cửa hậu). CWE-321/798.
2. **MinIO default creds** (`<REDACTED_MINIO_USER>:<REDACTED_MINIO_PASS>`, cổng 9000 mở Internet) → liệt kê/đọc/ghi/xoá **98 video dashcam** bằng chứng tài xế. CWE-798/1392.
- Kèm **HIGH**: ingestion telemetry/alert **không xác thực** (CWE-306) → bơm GPS/cảnh báo giả; **BOLA** theo dõi GPS mọi xe (CWE-639).
- **Ước lượng leak:** 15/15 user có PII + 98 object bằng chứng. Chi tiết: `P-136/README.md`.

### P-010 (VinStay) — 2 HIGH (scan code)
1. **JWT dev-fallback secret** đoán được khi `NODE_ENV≠production`/`JWT_SECRET` trống → giả mạo phiên.
2. **Commit nguyên Chrome profile** (`tech data/…`, 1875 file): cookie Google/Facebook thật, `Login Data` chứa mật khẩu đã lưu, PII — lộ vĩnh viễn trong lịch sử git. CWE-312/540/359. → **Khuyến nghị gỡ khỏi repo + xoay toàn bộ credential bị lộ NGAY.**

### P-143 — 1 HIGH (scan code)
- **Prompt injection gián tiếp**: văn bản OCR/PDF người dùng upload nối thẳng vào prompt LLM, không rào. OWASP LLM01. (+ context overflow, vài Low.)

### P-145 — 1 HIGH (API động)
- **Mật khẩu khởi tạo dùng chung `<REDACTED_PASSWORD>`** cho mọi nhân viên mới (code tự thừa nhận "ai biết email là đăng nhập được"). CWE-521/1392.

## 4. Nhận xét cho từng nhóm (chống "ngủ quên trong chiến thắng")
- **P-075, P-123, P-047**: nền tảng rất tốt (session/CSRF hoặc JWT chuẩn, phân quyền đối tượng chặt đã kiểm chứng động, phòng thủ prompt injection giữ vững kể cả injection gián tiếp nâng cao qua file). **Vẫn còn** điểm phải xử lý: P-047 endpoint reset-toàn-app không auth; P-123 injection email (bounded); P-075 đảm bảo tắt demo-login ở prod. Không được chủ quan.
- **P-136**: tính năng tốt nhưng bảo mật nền tảng thủng nặng (secret/creds hardcode, thiếu auth ingestion) — **ưu tiên sửa số 1**.
- **P-010**: logic backend NestJS khá chắc (ownership, SQL tham số hoá) nhưng bị hạ gục bởi rò rỉ secret/credential do thao tác repo — bài học về vệ sinh repo.
- **P-143**: kiến trúc tenant/SQL tốt; lớp agentic — đường OCR an toàn (vision, không nối chữ; mã OCR-injection cũ là code chết) nhưng **đường đối soát (reconciliation) chưa rào injection** (FINDING-09) — đúng trọng tâm cần vá.
- **P-145**: kỹ thuật tốt (cookie httpOnly, grounding RAG, scope theo khoa) nhưng detector injection bằng regex quá hẹp + mật khẩu chung — hai điểm dễ sửa, giá trị cao.
- **P-140**: mới là boilerplate; chưa đánh giá được vì chưa có logic/LLM/DB thật.

## 4b. Logic nghiệp vụ / race condition / data integrity
- **P-136 (dính):** `assign-vehicle` không khoá row/không unique constraint → **TOCTOU race**: 12 request song song tạo **5 ca ACTIVE** cho 1 tài xế (đã dọn). Ingestion không auth cũng là tấn công làm sai dữ liệu (bơm GPS/alert giả). Xem `P-136/README.md` F-07, F-03.
- **P-123 (an toàn):** UPSERT `ON CONFLICT` + `FOR UPDATE` + optimistic `lock_version` → chống double-submit/ghi đè. **P-075:** khoá `with_for_update` khi cập nhật (lý do nhóm chọn pipeline này). Hai nhóm này xử lý concurrency đúng.
- **Stress test:** chỉ đo bằng burst giới hạn (≤12 request); không flood gây outage. P-136/P-075/P-123/P-047 đều có rate-limit đăng nhập; P-047/P-145 có rate-limit gọi AI.

## 4c. Battery mở rộng (chi phí/context/memory/file/rate-limit/caching/injection-leak) — TẤT CẢ nhóm động
Chạy cho 5 nhóm có deploy (P-136 tự làm; P-047/P-075/P-123/P-145 qua subagent per-project). Mọi bản ghi test gắn nhãn `SECTEST-` + có `evidences/CLEANUP_P-xxx.md`.

| Nhóm | Chi phí/Input | Memory/Ctx | Cache | Rate-limit | File độc hại | Injection+Leak | Load/Race |
|---|---|---|---|---|---|---|---|
| P-136 | — | — | — | ❌ không có (ingest) | ⚠️ | N/A (agent echo) | ❌ race 5 ca + ghi sụp 82.5% |
| P-047 | ✅ max 2000 | ✅ bounded+nén | ✅ tách user | ⚠️ user-key (thiếu global) | ✅ 15/15 4xx | ✅ 10/10 từ chối | ✅ |
| P-075 | ✅ 3000/300 | ✅ | ✅ +trần $ | ✅ +chống spoof IP | ✅ sạch | ✅ VLM whitelist (0 canary) | ✅ advisory lock |
| P-123 | ✅ | ✅ snapshot tối thiểu | ✅ idempotency | ❌ login fail ở live | ✅ | ✅ end-to-end chặn | ⚠️ perf N+1 |
| P-145 | ✅ bounded | ✅ top_k=5 | ✅ | ❌ thiếu rate-limit | ✅ 16/16 fail-safe | ⚠️ detector bypass 9/9 (grounding chắn) | ✅ |

**Mức phủ battery theo nhóm (trung thực):** test đến đâu mỗi bề mặt cho phép, KHÔNG đồng đều.
- Load read+write nhiều bề mặt: **P-136, P-075, P-123, P-047** (và P-145 có load, write nhẹ). **P-010**: ngoài 30 POST nhanh `/assistant/chat`, nay đã **write-load động** `POST /bookings` ramp 1→50 (stub OTP/VietQR) → phát hiện **FINDING-08** (slot_taken giả do serialization gán nhầm; p99 ≤83ms, không sập); 181 bản ghi `SECTEST-` đã dọn sạch.
- Xem mục **"Giới hạn & phần CHƯA hoàn thành"** cuối file.

Phát hiện mới đáng kể (gồm đợt test động local 2026-10-13):
- **P-010 JWT forge XÁC NHẬN ĐỘNG** (HIGH) — token giả từ giá trị public trong repo → `GET /admin/field-hosts` 200, chiếm quyền admin; **gap mới**: bộ lọc `find_violations()` chỉ chạy khi `tainted` → jailbreak không qua listing lách được. **FINDING-07 (Low)**: không trần token/chi phí per-user, không `max_tokens`, không cache đáp án. **IDOR/BFLA xác nhận AN TOÀN động** (2 tenant+2 landlord + **host↔host** + **deposit happy-path** qua seed DB, chéo đối tượng/chức năng đều 404/403/401); upload **fail-safe**; **FINDING-08 (Low)**: slot_taken giả dưới tải ghi đồng thời. Luồng lập hợp đồng/PDF hạ nguồn (code thật) chạy động qua seed: authz an toàn (tải PDF chéo tenant → 404). Endpoint eKYC `scan`/`submit` **chưa hiện thực** (chỉ `loadOwned` → throw 503, không provider/cờ env để stub) ⇒ chỉ ownership gate là chạy động được, và đã an toàn.
- **P-140** (động) — `/api/v1/chat` **không auth + không giới hạn body** → DoS (MEDIUM, CWE-400/770); nhóm này trước đây tưởng "sạch".
- **P-143** (động, **định vị lại**) — FINDING-01 (OCR injection) hoá ra là **code chết** (chỉ trong test); vector injection THẬT là **FINDING-09 (MEDIUM, CWE-77/LLM01)** ở đường **đối soát** (`reconciliation/acl/gateway.py` nối thẳng mô tả/mã hàng vào prompt arbiter) — giảm nhẹ mạnh (model chỉ chọn từ danh sách code-side, tiền do code tính, luôn có người duyệt). `/auth/login` không rate-limit + lockout không atomic (12/15 lọt). Load/race sạch, XXE/XML-bomb fail-safe, **answer-cache theo tenant = điểm cộng**.
- **P-145 chat RAG e2e: PASS** — doc nhiễm độc retrieve được nhưng không lộ canary/system/tool (phòng thủ 5 tầng); detector INTAKE bypass 9/9 vẫn là MEDIUM riêng.
- **P-123 rate-limit login không hiệu lực ở production** (MEDIUM, CWE-307 — IP sau proxy Render phân mảnh bucket).
Điểm cộng: file-robustness fail-safe ở mọi nhóm; P-075/P-047/P-123 + chat RAG P-145 chặn prompt-injection + race tốt.

> Lưu ý minh bạch: khi test P-123 `/analyze`, subagent lỡ đẩy 1 case email-intake có sẵn (`a52e979b`) sang AI_REVIEWING và **đã khôi phục** về MANUAL_REVIEW. 32 case `SECTEST-` (P-123) + 5 changeset nháp rỗng (P-145) còn lại — SQL/ID dọn trong `CLEANUP_P-123.md`/`CLEANUP_P145.md` để nhóm tự chạy (không có API xoá).

## 5. Về "chiến dịch tấn công phá huỷ"
- Thực hiện **có kiểm soát + đảo ngược**: ví dụ P-136 tạo→xoá user ADMIN test, ghi→xoá object MinIO test (downtime gây ra = 0, không đụng dữ liệu thật).
- **Không** cố ý gây outage hạ tầng hay DROP toàn bộ DB trên dịch vụ live: với quyền API hiện có không đảm bảo khôi phục được, và đây là sản phẩm demo của chính các nhóm. Thay vào đó **chứng minh "cùng quyền này đủ để xoá sạch/leak" + ước lượng thiệt hại** (xem `P-136/README.md`).
- 3 nhóm strong (P-075/P-123/P-047) & P-145: không có lỗ hổng chiếm quyền để PoC phá huỷ → không có cơ sở tấn công phá huỷ.

## 6. Khuyến nghị ưu tiên
1. **P-136**: xoay `JWT_SECRET` (chỉ từ env, không default) + đổi root MinIO + đóng cổng 9000 + thêm auth cho ingestion + kiểm quyền theo đối tượng cho telemetry. **Gấp.**
2. **P-010**: `git rm` thư mục `tech data/`, purge lịch sử git, **xoay mọi credential đã lộ**; ép `NODE_ENV=production` + `JWT_SECRET` thật trong mọi pipeline.
3. **P-143**: rào prompt injection cho **đường đối soát (reconciliation)** — tách mô tả/mã hàng người dùng khỏi chỉ dẫn (delimiter + nhãn dữ liệu), giới hạn input (40KB→cắt), cân nhắc hậu kiểm. (Đường OCR hiện an toàn; mã OCR-injection cũ là code chết.)
4. **P-145**: mật khẩu khởi tạo ngẫu nhiên từng người; thay detector regex bằng tách cấu trúc + hậu kiểm/LLM-judge.
5. **P-047**: yêu cầu auth manager cho `/auth/reset` hoặc tắt ở prod.
6. **P-075/P-123**: xử lý các Low; đảm bảo cấu hình prod (tắt demo-login, kiểm chéo trích xuất email).

## 7. Giới hạn & phần chưa hoàn thành (trung thực — cập nhật 2026-10-13)
Phần lớn khoảng trống trước đây **đã được đóng** bằng (a) dựng các nhóm không-deploy chạy **local** để test động, và (b) chạy **injection RAG đầu-cuối** cho P-145. Dưới đây là trạng thái thật:

| Nhóm | Hạng mục | Trạng thái | Chi tiết |
|---|---|---|---|
| **P-010** | Prompt-injection / context / IDOR/BFLA / upload / write-load động | ✅ **ĐÃ ĐÓNG (local + stub provider)** | Dựng full stack local (NestJS + Postgres), **mock LLM** + **stub OTP/VietQR**. Xác nhận động: JWT forge (High), injection + gap `tainted`, XFF reset quota, **IDOR/BFLA an toàn** (2 tenant+2 landlord), **upload fail-safe**, **FINDING-08** slot_taken giả dưới tải ghi. **Đóng nốt động (seed DB cô lập)**: IDOR host↔host (hostA↔hostB → 404/409/403), deposit happy-path trọn vẹn (createDeposit → webhook ký đúng → PAID; IDOR deposit chéo 404/403; sai secret 401), luồng hợp đồng/eKYC hạ nguồn (seed VERIFIED → tải PDF hợp đồng niêm phong, authz an toàn) — **0 finding mới / 44 phép thử**. *Điểm không chạy động được — vì CHƯA hiện thực, không phải thiếu stub:* `identity.service.ts` `scan`/`submit` chỉ `loadOwned` → `void dto` → `throw` 503 vô điều kiện; không adapter/HTTP/cờ env ⇒ không có gì để stub kiểu OTP/VietQR (chỉ còn cách viết lại code nhóm = test code bịa → không làm). Ownership gate trước throw ĐÃ test động (chéo tenant 404); lập hợp đồng/PDF hạ nguồn là code thật, đã chạy qua seed. Độ nhạy model THẬT không đo (LLM mock). |
| **P-145** | Injection RAG **đầu-cuối** | ✅ **ĐÃ ĐÓNG (live)** | Tạo employee qua intake → publish doc nhiễm độc → chat. Doc **được retrieve (5 citations)** nhưng không lộ canary/system/tool → **PASS, phòng thủ 5 tầng**. Đã deactivate employee + supersede doc + SQL dọn. *Dư:* không cô lập được 1 lần grounded-LLM thuần (gate biến-động-cao luôn kèm chunk high-vol do corpus nhỏ). |
| **P-143** | Load/race/rate-limit + **injection/context/caching động** | ✅ **ĐÃ ĐÓNG (local)** | Docker compose full stack; load 1→50 (0×5xx), race serialize đúng, XXE/billion-laughs FAIL; FINDING-08 rate-limit/lockout. **Injection/context/caching ĐÃ test động** qua **mock LLM in-process** (monkeypatch SDK, không cần key, URL hard-code vô can): FINDING-09 injection đối soát (Medium), context 40KB không cắt, answer-cache theo tenant (tốt), FINDING-01 OCR là code chết. *Dư:* chỉ còn phán quyết model THẬT (xem dưới). |
| **P-140** | Battery động | ✅ **ĐÃ ĐÓNG (local)** | Dựng local; xác nhận DoS `/api/v1/chat` (Medium). LLM chưa nối ở bản hiện tại → injection/tool chưa có bề mặt (test lại khi nhóm cài logic). |
| **P-123** | Phán quyết Gemini model **thật** dưới injection | ✅ **ĐÃ QUAN SÁT** | Gemini thật chạy được (dù free-tier chập chờn): model chỉ chuẩn hoá khiếu nại, **không lộ system prompt**. |
| **P-075, P-143** | Phán quyết VLM/model **thật** dưới injection | ⚠️ **GIỚI HẠN ĐÃ CHẤP NHẬN (mentor chốt 2026-10-13)** | P-075 VLM live chạy `mock`; P-143 OpenRouter URL hard-code HTTPS + không có key → cần **API key trả phí ở staging** (ngoài tầm reviewer). Phòng thủ **QUANH model** (whitelist strip payload / grounding / taint-filter) đã xác nhận — độc lập với model. Mentor chấp nhận đây là giới hạn; xem `USER-DECISIONS.md`. |

**Kết luận:** test động phủ **cả 8 nhóm** (5 trên deploy + 3 dựng local) + injection RAG đầu-cuối P-145. Toàn bộ tầng phòng thủ quanh model đã kiểm cho mọi nhóm. Mục duy nhất còn lại — độ nhạy *nội tại* của model proprietary (P-075/P-143) — cần API key trả phí ở staging và đã được **mentor chấp nhận là giới hạn**. Review hoàn tất trong phạm vi được cấp phép. Mọi bằng chứng + script ở `reviews/P-xxx/`.
