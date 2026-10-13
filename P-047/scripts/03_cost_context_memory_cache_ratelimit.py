#!/usr/bin/env python3
"""P-047 MoveInMate — Battery mở rộng (phần A).

Test ĐỘNG qua API (không UI), môi trường được cấp phép (mentor sở hữu).
Bao phủ: (1) quản lý chi phí/độ dài message, (2) memory/turns, (3) caching,
(4) rate-limit chat (ngưỡng + keying theo user + thử bypass header).

Rào an toàn: pacing giữa request, burst rate-limit cap cứng, dừng nếu >=3 lỗi 5xx
liên tiếp. Chỉ dùng tài khoản test được cấp. KHÔNG brute-force secret.
"""
import json
import time
import urllib.request
import urllib.error

BASE = "https://<REDACTED_DEPLOY>/api/v1"
EVID = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-047/evidences/03_cost_context_memory_cache_ratelimit.json"

results = {"base": BASE, "started": time.strftime("%Y-%m-%d %H:%M:%S"), "tests": {}}
_consecutive_5xx = 0


def _req(method, path, token=None, json_body=None, extra_headers=None, timeout=90):
    """Trả (status, elapsed_s, parsed_or_text)."""
    global _consecutive_5xx
    url = BASE + path
    headers = {"Accept": "application/json"}
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            status = r.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        status = e.code
    except Exception as e:  # noqa: BLE001
        return (-1, time.monotonic() - t0, f"EXC: {type(e).__name__}: {e}")
    elapsed = time.monotonic() - t0
    if status >= 500:
        _consecutive_5xx += 1
    else:
        _consecutive_5xx = 0
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = body[:600]
    return (status, round(elapsed, 3), parsed)


def login(username, password):
    status, _, body = _req("POST", "/auth/login", json_body={"username": username, "password": password})
    assert status == 200, f"login failed {status} {body}"
    return body["access_token"]


def short(x, n=500):
    s = x if isinstance(x, str) else json.dumps(x, ensure_ascii=False)
    return s[:n]


def answer_of(parsed):
    if isinstance(parsed, dict):
        return parsed.get("answer") or parsed.get("message") or parsed.get("detail") or ""
    return str(parsed)


print("Login...")
TOKEN = login("user", "<REDACTED_PASSWORD>")

# ---------------------------------------------------------------------------
# TEST 1: Quản lý chi phí / giới hạn độ dài message (code: message max_length=2000)
# ---------------------------------------------------------------------------
print("\n[1] Cost/length guard")
t1 = {"desc": "Gửi message quá dài: 2000 (biên), 2001, 50k, 200k ký tự", "cases": []}
for n in (2000, 2001, 50_000, 200_000):
    conv = f"len-{n}-{int(time.time())}"
    msg = "A" * n
    status, el, body = _req("POST", "/agent/chat", TOKEN, {
        "project_id": "moveinmate", "conversation_id": conv, "message": msg, "language": "vi"})
    ans = answer_of(body)
    t1["cases"].append({
        "chars": n, "status": status, "elapsed_s": el,
        "accepted": status == 200,
        "resp": short(body, 400),
    })
    print(f"  {n:>7} chars -> HTTP {status} ({el}s)")
    time.sleep(0.4)
results["tests"]["1_cost_length"] = t1

# ---------------------------------------------------------------------------
# TEST 2: Memory / turns trong 1 conversation_id
# ---------------------------------------------------------------------------
print("\n[2] Memory / turns")
conv = f"mem-{int(time.time())}"
CANARY = "MEM-CANARY-7731"
turns = []
seq = [
    f"Ghi nhớ giúp tôi: mã tham chiếu hồ sơ của tôi là {CANARY}. Xác nhận đã nhớ.",
    "Thủ tục đăng ký xe máy cần giấy tờ gì?",
    "Thời gian chuyển vào ban ngày hay cũng được buổi tối?",
    "Cảm ơn. Nội quy về vật nuôi thế nào?",
    "Phí quản lý đóng theo tháng hay quý?",
    f"Mã tham chiếu hồ sơ mà tôi nói ở lượt ĐẦU TIÊN là gì? Trả lời đúng mã.",
]
for i, m in enumerate(seq):
    status, el, body = _req("POST", "/agent/chat", TOKEN, {
        "project_id": "moveinmate", "conversation_id": conv, "message": m, "language": "vi"})
    ans = answer_of(body)
    turns.append({"turn": i + 1, "status": status, "elapsed_s": el, "msg": m[:60], "answer": short(ans, 300)})
    print(f"  turn {i+1} -> HTTP {status} ({el}s)")
    if status == 429:
        turns[-1]["note"] = "rate limited mid-test"
        break
    time.sleep(0.5)
last_answer = turns[-1]["answer"] if turns else ""
results["tests"]["2_memory_turns"] = {
    "desc": "Nhắc fact ở lượt 1, hỏi lại sau 5 lượt (code: compact_messages max_messages=18, max_chars=14000, bounded+compressed)",
    "conversation_id": conv,
    "canary": CANARY,
    "recalled_canary": CANARY in last_answer,
    "turns": turns,
}

# ---------------------------------------------------------------------------
# TEST 3: Caching — chat có cache không? (code: run_agent_chat KHÔNG dùng private_results)
# ---------------------------------------------------------------------------
print("\n[3] Caching (chat)")
ident_msg = "Phí gửi xe máy hàng tháng là bao nhiêu?"
cache_cases = []
for k in range(2):
    conv = f"cache-{k}-{int(time.time())}"  # conversation_id khác nhau, cùng message
    status, el, body = _req("POST", "/agent/chat", TOKEN, {
        "project_id": "moveinmate", "conversation_id": conv, "message": ident_msg, "language": "vi"})
    cache_cases.append({"iter": k, "status": status, "elapsed_s": el, "answer": short(answer_of(body), 300)})
    print(f"  chat repeat {k} -> HTTP {status} ({el}s)")
    time.sleep(0.4)
same = len({c["answer"] for c in cache_cases if c["status"] == 200}) == 1 and len(cache_cases) == 2
results["tests"]["3_caching_chat"] = {
    "desc": "Gửi cùng message qua 2 conversation_id khác nhau; chat không có result-cache => mỗi lần là 1 LLM call",
    "cases": cache_cases,
    "byte_identical_answers": same,
    "note": "private_results chỉ cache TTS/OCR, key=(auth_subject, session_id, kind, digest) => tách theo user+session",
}

# ---------------------------------------------------------------------------
# TEST 4: Rate limit chat — ngưỡng (code 30/10min), keying theo user, bypass header
# ---------------------------------------------------------------------------
print("\n[4] Rate-limit chat (controlled burst, cap 20)")
rl = {"desc": "Chat thêm cho tới khi 429; xác định ngưỡng ~30/10min keyed by auth_subject",
      "config_from_code": "chat_requests_per_10_minutes=30; reserve_usage subject=context.auth_subject (per-user, NOT per-IP)",
      "probe": [], "first_429_at_global_count": None}
# Đếm các chat đã dùng trong window này (test1 là 422 -> KHÔNG tính; test2+test3 200 -> tính)
used_200 = sum(1 for t in turns if t["status"] == 200) + sum(1 for c in cache_cases if c["status"] == 200)
rl["chat_200_before_probe"] = used_200
BURST_CAP = 20
hit429 = False
for k in range(BURST_CAP):
    status, el, body = _req("POST", "/agent/chat", TOKEN, {
        "project_id": "moveinmate", "conversation_id": f"rl-{k}-{int(time.time())}",
        "message": "hi", "language": "vi"})
    used_200 += 1 if status == 200 else 0
    rl["probe"].append({"k": k, "status": status, "elapsed_s": el, "resp": short(body, 160)})
    print(f"  probe {k} -> HTTP {status} ({el}s)")
    if status == 429 and not hit429:
        hit429 = True
        rl["first_429_at_global_count"] = used_200 + 1  # approx request number in window
        # đã thấy 429 -> không cần burst tiếp
        break
    if _consecutive_5xx >= 3:
        rl["aborted"] = "3x consecutive 5xx — stopped per safety rule"
        break
    time.sleep(0.3)
rl["hit_429"] = hit429

# Keying: cùng user, token MỚI (session khác) -> vẫn phải bị limit (per auth_subject)
if hit429:
    token2 = login("user", "<REDACTED_PASSWORD>")
    s2, e2, b2 = _req("POST", "/agent/chat", token2, {
        "project_id": "moveinmate", "conversation_id": f"rl-newsess-{int(time.time())}",
        "message": "hi", "language": "vi"})
    rl["keying_new_session_same_user"] = {"status": s2, "elapsed_s": e2, "resp": short(b2, 160),
        "still_limited": s2 == 429,
        "interpretation": "429 => limit theo user(auth_subject), không theo session"}
    # Bypass bằng header giả IP
    s3, e3, b3 = _req("POST", "/agent/chat", TOKEN, {
        "project_id": "moveinmate", "conversation_id": f"rl-xff-{int(time.time())}",
        "message": "hi", "language": "vi"},
        extra_headers={"X-Forwarded-For": "9.9.9.9", "X-Real-IP": "9.9.9.9", "CF-Connecting-IP": "9.9.9.9"})
    rl["bypass_ip_header"] = {"status": s3, "elapsed_s": e3, "resp": short(b3, 160),
        "bypassed": s3 == 200,
        "interpretation": "429 => đổi header IP KHÔNG bypass (limit keyed by user)"}
results["tests"]["4_rate_limit_chat"] = rl

results["ended"] = time.strftime("%Y-%m-%d %H:%M:%S")
with open(EVID, "w") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)
print(f"\nSaved -> {EVID}")
print("SUMMARY:")
print("  1 length guard: 2000 accepted?", t1["cases"][0]["accepted"], "| >2000 blocked?",
      all(not c["accepted"] for c in t1["cases"][1:]))
print("  2 memory recall canary:", results["tests"]["2_memory_turns"]["recalled_canary"])
print("  3 chat byte-identical (cached?):", results["tests"]["3_caching_chat"]["byte_identical_answers"])
print("  4 hit 429:", rl["hit_429"], "| approx threshold req#:", rl["first_429_at_global_count"])
