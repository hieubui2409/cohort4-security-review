# P-140 — Báo cáo rà soát bảo mật (SCAN TĨNH)

- **Phạm vi:** đọc code tĩnh (không chạy, không test động, không sửa code) repo `P-140` (FastAPI + LangGraph agent — repo nhỏ).
- **Ngày rà soát:** 2026-10-13 (+07).
- **Người thực hiện:** <REDACTED_EMAIL> (hỗ trợ bởi Claude Code).

## Kết luận nhanh

**P-140 gần như là một BOILERPLATE/TEMPLATE chưa cài logic thật — KHÔNG có lỗ hổng bảo mật thực sự đáng kể.**

- LLM **chưa được nối**: `src/agents/nodes/example_node.py` chỉ nối chuỗi (`f"Phân tích: {query}"`, có `# TODO`), `src/services/llm.py:get_llm()` không nơi nào gọi, các `@tool` (`search_knowledge`, `calculate`) không bind vào graph/LLM. → Chưa có prompt injection, chưa có RAG/tool thực thi.
- Không có database/ORM nào được dùng (phần DB trong `requirements.txt` còn comment), không có xử lý file/upload, không có auth/phân quyền để mà IDOR.
- Không có secret thật bị commit; `.env.example` chỉ chứa placeholder (`sk-your-key-here`); `openai_api_key` mặc định rỗng.
- Điểm cộng: calculator dùng AST an toàn (không `eval`), `Dockerfile` chạy non-root, input có `max_length=5000`.

Chỉ còn vài lưu ý hardening (Low/Info) cho khi nhóm cài logic thật.

## Bảng tổng hợp mức độ

| # | Severity | Phân loại | Tiêu đề | File |
|---|----------|-----------|---------|------|
| 01 | Low | auth / rate-limit | Endpoint agent `/chat`, `/status` không xác thực | `src/api/routes.py:9-24` |
| 02 | Low | info disclosure | Trả nguyên `str(e)` trong lỗi 500 | `src/api/routes.py:18-19` |
| 03 | Info | prompt-injection (tiềm ẩn) | Khi nối `message` vào prompt LLM (chưa làm) sẽ phát sinh injection | `src/agents/nodes/example_node.py:4-12` |
| 04 | Info | misconfiguration | CORS `allow_credentials` + methods/headers `*` (origins vẫn tường minh) | `src/main.py:26-32` |

---

## [P-140] FINDING-01: Endpoint agent không xác thực

- **Phân loại / Category:** auth / rate-limit
- **Mã định danh:** OWASP **API2:2023 Broken Authentication** (thiếu xác thực trên endpoint) — https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ ; liên quan CWE-306 (Missing Authentication for Critical Function).
- **Mức độ / Severity:** Low (hiện là stub; nâng lên nếu nối LLM thật)
- **Thời gian phát hiện:** 2026-10-13 15:40 (+07)
- **Link/endpoint:** `POST /api/v1/chat`, `GET /api/v1/status`
- **Luồng (flow):** client gọi `/chat` → `agent.ainvoke({"query": message})` không cần token.

### Mô tả
`routes.py` không gắn dependency xác thực nào. Hiện `agent` chỉ nối chuỗi nên tác hại ~0. Khi `analyze_node` được nối với LLM thật (`get_llm()`), đây thành endpoint LLM mở — lạm dụng chi phí/DoS và bề mặt prompt injection cho bất kỳ ai.

### Input/Output (trích code)
```
src/api/routes.py:9-17
    @router.post("/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest) -> ChatResponse:
        result = await agent.ainvoke({"query": request.message})
        ...
```

### Tác động
Hiện tại: thấp. Tương lai (khi nối LLM): lạm dụng token/chi phí, DoS, bề mặt injection.

### Khuyến nghị sửa
Thêm xác thực (API key/JWT) + rate limit trước khi nối LLM thật; giới hạn độ dài/định dạng input (đã có `max_length=5000`).

### Bằng chứng
- `evidences/01_unauth_endpoint_and_error_leak.txt`

---

## [P-140] FINDING-02: Rò chi tiết lỗi nội bộ trong phản hồi 500

- **Phân loại / Category:** info disclosure
- **Mã định danh:** **CWE-209** Generation of Error Message Containing Sensitive Information — https://cwe.mitre.org/data/definitions/209.html
- **Mức độ / Severity:** Low
- **Thời gian phát hiện:** 2026-10-13 15:45 (+07)
- **Link/endpoint:** `POST /api/v1/chat`

### Mô tả
`except Exception as e: raise HTTPException(status_code=500, detail=str(e))` trả nguyên thông điệp exception cho client — có thể lộ chi tiết nội bộ (đường dẫn, tên lib, cấu hình, thậm chí mảnh khoá nếu lỗi từ client LLM).

### Input/Output (trích code)
```
src/api/routes.py:18-19
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

### Tác động
Lộ thông tin hỗ trợ do thám (information leakage).

### Khuyến nghị sửa
Trả thông điệp chung ("Lỗi xử lý nội bộ"), log chi tiết phía server (có request id), không đưa `str(e)` ra client.

### Bằng chứng
- `evidences/01_unauth_endpoint_and_error_leak.txt`

---

## [P-140] FINDING-03: (Tiềm ẩn) Prompt injection khi nối input vào LLM

- **Phân loại / Category:** prompt-injection (tiềm ẩn — chưa phát sinh)
- **Mã định danh:** OWASP **LLM01:2025 Prompt Injection** — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- **Mức độ / Severity:** Info (chưa có code gọi LLM)
- **Thời gian phát hiện:** 2026-10-13 15:50 (+07)

### Mô tả
`analyze_node`/`respond_node` hiện chỉ nối chuỗi, có `# TODO: gọi LLM, search vector DB`. Khi nhóm hiện thực việc đưa `request.message` (và tương lai là kết quả RAG/tài liệu) vào prompt, cần rào input và phân tách rõ dữ liệu vs chỉ thị ngay từ đầu — đặc biệt endpoint này đang không auth.

### Input (trích code)
```
src/agents/nodes/example_node.py:4-12
    query = state.get("query", "")
    analysis = f"Phân tích: {query}"   # TODO: gọi LLM thực tế
```

### Khuyến nghị sửa
Khi nối LLM: bao input/tài liệu trong delimiter, chỉ dẫn "chỉ là dữ liệu", không đặt bí mật trong prompt, validate output; kết hợp FINDING-01 (auth + rate limit).

### Bằng chứng
- `evidences/01_unauth_endpoint_and_error_leak.txt`

---

## [P-140] FINDING-04: Cấu hình CORS cho phép credentials với methods/headers `*`

- **Phân loại / Category:** misconfiguration
- **Mã định danh:** OWASP **API8:2023 Security Misconfiguration** — https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- **Mức độ / Severity:** Info
- **Thời gian phát hiện:** 2026-10-13 15:55 (+07)

### Mô tả
`main.py` bật `allow_credentials=True` cùng `allow_methods=["*"]`, `allow_headers=["*"]`. `allow_origins` lấy từ config và là danh sách tường minh (mặc định `http://localhost:3000`), KHÔNG phải `"*"` nên hiện chấp nhận được. Lưu ý: tuyệt đối không dùng origin `"*"` chung với `allow_credentials=True`.

### Input (trích code)
```
src/main.py:26-32
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
```

### Khuyến nghị sửa
Giữ origins tường minh (đang đúng); thu hẹp methods/headers về đúng cái dùng khi lên production.

### Bằng chứng
- `evidences/01_unauth_endpoint_and_error_leak.txt`

---

## Battery (đánh giá TĨNH — boilerplate, không có deploy)
P-140 hiện là **khung mẫu (boilerplate) chưa cài logic thật**: không có LLM nối thật (node chỉ nối chuỗi, `get_llm()` không được gọi, tool không bind), không DB/upload/auth nghiệp vụ; phần Python thực chỉ là script logging (`log_hook`, `submit_log` với `BATCH_LIMIT`). Vì vậy **không có bề mặt cho hầu hết hạng mục battery** (chi phí/context/memory/cache/rate-limit/file/injection động/load). Chỉ có ghi chú hardening đã nêu ở trên (`/chat` không auth echo + lộ `str(e)` ở lỗi 500; prompt-injection tiềm ẩn khi nối LLM; CORS credentials + methods/headers `*`).

> Khi nhóm cài logic thật (LLM/DB/upload), phải chạy lại toàn bộ battery (đặc biệt: giới hạn input/chi phí, rate-limit, file robustness, prompt-injection + lộ system prompt/tool, load/race).

---

## Bổ sung: test động local

- **Ngày test động:** 2026-10-13 (+07). **Người thực hiện:** <REDACTED_EMAIL> (hỗ trợ bởi Claude Code).
- **Phạm vi:** DỰNG P-140 CHẠY LOCAL rồi test ĐỘNG qua HTTP API (không UI) để XÁC NHẬN các kết luận tĩnh, không mặc định "sạch".

### Cách dựng (có kiểm soát + khôi phục)
- **Không dùng Docker** (tránh build image từ repo không tin cậy); thay bằng **venv NGOÀI repo** tại scratchpad, Python 3.12 (repo yêu cầu 3.11 — không có sẵn, 3.12 tương thích FastAPI/LangGraph).
- Chỉ cài deps tối thiểu cho chuỗi import chạy app: `fastapi, uvicorn, pydantic, pydantic-settings, python-dotenv, langgraph, httpx`.
- **KHÔNG CẦN KEY THẬT / KHÔNG STUB LLM:** chuỗi import khi chạy app là `main → api.routes → agents.graph → agents.nodes.example_node → agents.state`, **không** chạm `services/llm.py` hay `langchain_openai`. Chạy với `OPENAI_API_KEY=""` thành công → xác nhận LLM **chưa được nối**.
- **An toàn khi chạy code lạ:** script test đặt NGOÀI repo (`reviews/P-140/scripts/`), chạy bằng `python -I` (cô lập, bỏ qua env/sys.path người dùng), chỉ dùng stdlib, truyền `base_url` qua tham số, **không** import gì từ repo. Server bind **127.0.0.1:8140** (chỉ localhost). Dọn: `kill` tiến trình sau khi xong — đã **xác nhận DOWN**.
- Lưu ý môi trường: scratchpad dùng chung có file rác `enum.py` (của review P-123) che khuất stdlib khi cwd là scratchpad gốc → đã xử lý bằng cách tạo/chạy venv từ thư mục rỗng `p140-run/`. (Không đụng P-123 hay project khác.)

### Đã chạy được? CÓ.
Server lên (`GET /health → 200 {"status":"ok","env":"development"}`). OpenAPI báo đúng 3 path: `/api/v1/chat`, `/api/v1/status`, `/health`.

### Kết quả xác nhận các finding tĩnh
| Finding tĩnh | Kết quả test động |
|---|---|
| 01 — endpoint không auth | **XÁC NHẬN**: `/api/v1/chat`, `/api/v1/status` trả 200 không cần credential. Tác hại hiện tại vẫn thấp (agent chỉ nối chuỗi). |
| 02 — rò `str(e)` ở lỗi 500 | **KHÔNG tái hiện được qua API**: mọi input xấu bị chặn ở tầng validation (422) *trước khi* tới agent; agent stub không ném exception → nhánh `except` (CWE-209) hiện **không reachable động**. Vẫn là nợ kỹ thuật cần sửa trước khi nối LLM. |
| 03 — prompt injection (tiềm ẩn) | **XÁC NHẬN chỉ là tiềm ẩn**: 5 payload injection (gồm "ignore all previous…", "reveal system prompt", đòi `OPENAI_API_KEY`/env, markers `{{7*7}}`) đều bị **echo nguyên văn**, không có LLM, không lộ system prompt/tool, không SSTI. Không có bề mặt injection thật ở bản hiện tại. |
| 04 — CORS credentials + methods/headers `*` | **XÁC NHẬN cấu hình hiện tại AN TOÀN**: origin hợp lệ (`http://localhost:3000`) được phản chiếu `ACAO` + `ACAC: true`; origin lạ (`https://evil.example`) **không** được phản chiếu ACAO và preflight trả **400 "Disallowed CORS origin"**. Rủi ro chỉ phát sinh nếu nhóm đặt `CORS_ORIGINS="*"`. |

### FINDING MỚI (chỉ lộ qua test động)

#### [P-140] FINDING-05: `/api/v1/chat` (không auth) không giới hạn kích thước request body → cạn tài nguyên (DoS)
- **Phân loại:** resource exhaustion / DoS.
- **Mã định danh:** **CWE-400** Uncontrolled Resource Consumption (https://cwe.mitre.org/data/definitions/400.html); **CWE-770** Allocation of Resources Without Limits or Throttling (https://cwe.mitre.org/data/definitions/770.html); OWASP **API4:2023 Unrestricted Resource Consumption** (https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).
- **Mức độ:** **Medium** (không auth, không rate limit, 1 worker uvicorn mặc định; kẻ tấn công từ xa gây tốn RAM/CPU).
- **Thời gian phát hiện:** 2026-10-13 23:07 (+07). **Endpoint:** `POST /api/v1/chat`.
- **Mô tả:** `max_length=5000` trong `ChatRequest` (được static review tính là điểm cộng) chỉ được áp **SAU KHI** Starlette/FastAPI đã **buffer toàn bộ body vào RAM và parse JSON**. Không có giới hạn kích thước body ở tầng ASGI/app. Body khổng lồ vẫn bị nạp + parse rồi mới trả 422.
- **Bằng chứng (đo thực tế):**
  ```
  body   1MB -> 422 in   69ms
  body  10MB -> 422 in  199ms
  body  50MB -> 422 in 1055ms
  body 100MB -> 422 in 1853ms
  body 200MB -> 422 in 4739ms   # ~tuyến tính, 200MB = ~4.7s CPU+RAM cho 1 request không auth
  ```
- **Tác động:** vài request body lớn song song (endpoint mở, không rate limit) đủ chiếm worker và đẩy RAM → từ chối dịch vụ. (Server không crash trong test đơn luồng nhưng chi phí tuyến tính theo kích thước.)
- **Khuyến nghị:** thêm giới hạn kích thước body (reverse proxy `client_max_body_size`, hoặc middleware kiểm tra `Content-Length`/`content-length` và chặn sớm), đọc body theo stream có ngưỡng, kèm rate limit + auth (FINDING-01).

#### [P-140] FINDING-06: Thiếu security headers trên response (hardening)
- **Phân loại:** misconfiguration / hardening. **Mã:** OWASP **API8:2023 Security Misconfiguration**; liên quan CWE-693 (Protection Mechanism Failure).
- **Mức độ:** Info/Low.
- **Mô tả:** Response không có `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `Cache-Control`. Chỉ có `server: uvicorn`, `content-type`, `vary: Origin`.
- **Khuyến nghị:** thêm middleware set các security header mặc định khi lên production.

### Robustness / validation (điểm cộng — xác nhận động)
- Input validation chắc: empty (`min_length`), thiếu field, sai kiểu, `>5000` ký tự, JSON lỗi, body rỗng, array thay vì object, null byte → đều **422** đúng.
- Sai HTTP method (`GET /api/v1/chat`, `DELETE`, `POST /health`) → **405** đúng.
- Unicode/control chars được echo nguyên văn (stub) — không lỗi.

### Load test (ramp tới ~50, read + write)
Ghi `SECTEST-`; **lưu ý: `/chat` KHÔNG persist gì (không DB/ORM nào được dùng)** → payload `SECTEST-` không để lại bản ghi phía server, **không cần dọn**.

READ — `GET /api/v1/status` (40 req/luồng):
```
conc   1  rps=152  p50=3.8   p95=18.6  p99=26.9   0 lỗi
conc  10  rps=261  p50=36.3  p95=60.1  p99=68.6   0 lỗi
conc  20  rps=307  p50=53.5  p95=126   p99=195    0 lỗi
conc  35  rps=377  p50=78.6  p95=197   p99=253    0 lỗi
conc  50  rps=543  p50=76.0  p95=167   p99=193    0 lỗi
```
WRITE — `POST /api/v1/chat` (40 req/luồng):
```
conc   1  rps=44.7  p50=18.8  p95=59.9  p99=120   0 lỗi
conc  10  rps=63.5  p50=130   p95=333   p99=362   0 lỗi
conc  20  rps=78.4  p50=220   p95=521   p99=616   0 lỗi
conc  35  rps=83.0  p50=397   p95=663   p99=768   0 lỗi
conc  50  rps=165   p50=300   p95=457   p99=492   0 lỗi
```
- **Knee (write):** độ trễ bắt đầu dốc từ ~conc 10–20 (p50 18ms→130ms→220ms), throughput bão hoà ~80 rps/worker — giới hạn do **1 worker uvicorn + overhead async của LangGraph** dù node chỉ nối chuỗi. READ nhẹ hơn nhiều (chỉ trả dict tĩnh).
- **0 lỗi / 0 5xx** ở mọi mức tới conc=50: server ổn định, không crash, không rò lỗi dưới tải. (Kết hợp FINDING-05: throughput thấp + không rate limit = dễ bị bão hoà nếu không có proxy/limit.)

### Phần nào BỊ CHẶN / không test được + lý do
- **Prompt injection nâng cao / indirect / lộ system prompt + tool:** không có LLM nối → không có bề mặt. Không thể test động; sẽ phải chạy lại khi nhóm nối LLM thật.
- **Tool `calculate` (DoS qua `ast.Pow`, ví dụ `9**9**9`):** tool **không bind** vào graph/LLM nên **không reachable qua API** — chỉ là rủi ro tĩnh nếu sau này bind tool (nên chặn số mũ lớn). Không test động được.
- **File robustness (malformed upload):** không có endpoint upload/parse file → không áp dụng.
- **IDOR/BFLA:** không có auth/định danh tài nguyên/đối tượng nghiệp vụ → không có bề mặt.
- **Nhánh lỗi 500 (`str(e)`):** stub không ném exception; validation chặn trước → không reachable động (xem Finding 02).

### Tóm tắt test động
Dựng được (CÓ, không cần key, LLM chưa nối). Test động đã chạy: discovery/OpenAPI, authz (mở — xác nhận), validation/robustness (chắc), injection ngây thơ→nâng cao (chỉ echo, không bề mặt), CORS (cấu hình an toàn), body-size DoS, security headers, load read+write tới conc=50. **Finding mới:** FINDING-05 (body-size DoS, Medium — chỉ lộ qua test động) và FINDING-06 (thiếu security headers, Info/Low). Các finding tĩnh 01/03/04 được xác nhận; 02 không reachable động với bản stub hiện tại.

### Bằng chứng (evidences/)
- `02_dynamic_probes.txt` — discovery, authz, validation, robustness, injection, CORS, method.
- `03_cors_headers_bodysize.txt` — CORS header (case-insensitive), security headers, đo body-size DoS.
- `04_load_test.txt` — load test read/write ramp tới conc=50.
- Script: `scripts/dyn_probe.py`, `scripts/load_test.py` (chạy `python -I <script> <base_url>`, stdlib, ngoài repo).
