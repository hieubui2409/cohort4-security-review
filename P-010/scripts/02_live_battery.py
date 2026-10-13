#!/usr/bin/env python3
"""
P-010 — Battery ĐỘNG trên bề mặt công khai thật (/api/v1). LLM không test được (ai-engine 503),
nhưng kiểm được: throttle/rate-limit (@Throttle 20/60s), body-limit 256kb (413), guest-quota, swagger.
"""
import json, time, concurrent.futures as cf
import requests
B = "https://<REDACTED_DEPLOY>"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-010/evidences"
CHAT = f"{B}/api/v1/assistant/chat"
out = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "base": B, "tests": {}}

def post(body, hdr=None):
    try:
        r = requests.post(CHAT, json=body, headers=hdr or {}, timeout=20)
        return r.status_code, len(r.content)
    except Exception as e:
        return 0, str(e)[:60]

# 1) body-limit 256kb -> kỳ vọng 413
big = {"messages": [{"role": "user", "content": "A" * (300*1024)}], "locale": "vi"}
sc, n = post(big)
out["tests"]["body_limit_300kb"] = {"status": sc, "expect": "413 Payload Too Large"}
print("body 300kb ->", sc)

# 2) throttle: bắn 30 request nhanh -> kỳ vọng xuất hiện 429
codes = {}
def one(i):
    s, _ = post({"messages": [{"role": "user", "content": "studio dưới 8 triệu"}], "locale": "vi"})
    return s
with cf.ThreadPoolExecutor(max_workers=8) as ex:
    for s in ex.map(one, range(30)):
        codes[s] = codes.get(s, 0) + 1
out["tests"]["throttle_30_rapid"] = {"codes": codes, "expect": "có 429 (throttle 20/60s) hoặc 401 (guest quota)"}
print("throttle 30 ->", codes)

# 3) guest-quota bypass? đổi X-Forwarded-For có reset quota/throttle không
codes2 = {}
for i in range(12):
    s, _ = post({"messages": [{"role": "user", "content": "hi"}], "locale": "vi"},
                hdr={"X-Forwarded-For": f"9.9.9.{i}"})
    codes2[s] = codes2.get(s, 0) + 1
out["tests"]["xff_rotate_12"] = {"codes": codes2, "note": "nếu toàn 200/503 (không 429) khi xoay IP => quota/throttle theo IP có thể bypass bằng XFF"}
print("xff rotate ->", codes2)

# 4) swagger công khai?
for p in ["/api/docs", "/api/docs-json", "/api"]:
    try:
        r = requests.get(f"{B}{p}", timeout=15)
        out["tests"][f"swagger{p}"] = r.status_code
        print(f"GET {p} ->", r.status_code)
    except Exception as e:
        out["tests"][f"swagger{p}"] = str(e)[:40]

out["note"] = "ai-engine upstream 503 (deploy chưa cấu hình AI key) -> KHÔNG thể test hành vi LLM/prompt-injection động. Các mục auth/upload/DB khác của P-010 không có tài khoản live (không handoff) -> đánh giá qua scan code (xem README chính)."
json.dump(out, open(f"{OUT}/07_live_battery.json", "w"), ensure_ascii=False, indent=2)
print("saved ->", f"{OUT}/07_live_battery.json")
