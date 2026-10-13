#!/usr/bin/env python3
"""Battery 4 — Rate limiting (touch lightly).

  - Login limiter: code says 10 failures / 5 min per (client.host + email), process-local,
    only failed attempts count. Verify the 429 onset against a THROWAWAY non-existent email
    (never locks a real demo account).
  - Header bypass: resend with spoofed X-Forwarded-For / X-Real-IP / X-Client-IP; the limiter
    uses request.client.host (real socket), so spoofing must NOT reset the counter.
  - General endpoint: light burst of GET /reports (<=25, under the 30 cap) to see whether a
    per-minute guard (PublicDemoGuard 120/min) is active and whether reads stay 200.
"""
import sys, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _common import BASE, H, login, save, body_snip, CREDS
import requests

out = {"base": BASE, "login_limiter": [], "header_bypass": [], "read_burst": {}}
VICTIM = "<REDACTED_EMAIL>"  # non-existent, keeps the bucket isolated from real users

# 1) find 429 onset: up to 13 sequential bad logins, same (proxy) IP + email
onset = None
for i in range(13):
    r = requests.post(f"{BASE}/auth/login", json={"email": VICTIM, "password": "wrong-pass"}, timeout=20)
    code = None
    try:
        code = r.json().get("error", {}).get("code")
    except Exception:
        pass
    out["login_limiter"].append({"i": i + 1, "status": r.status_code, "code": code})
    if r.status_code == 429 and onset is None:
        onset = i + 1
    print(f"login attempt {i+1}: {r.status_code} {code}")
    if r.status_code >= 500:
        break
out["login_429_onset_attempt"] = onset

# 2) header spoof after limiter already tripped -> must stay 429 (no reset)
for hdrs in [
    {"X-Forwarded-For": "8.8.8.8"},
    {"X-Real-IP": "9.9.9.9"},
    {"X-Forwarded-For": "1.2.3.4, 5.6.7.8", "X-Client-IP": "2.2.2.2"},
]:
    r = requests.post(f"{BASE}/auth/login", json={"email": VICTIM, "password": "wrong-pass"},
                      headers=hdrs, timeout=20)
    code = None
    try:
        code = r.json().get("error", {}).get("code")
    except Exception:
        pass
    out["header_bypass"].append({"headers": hdrs, "status": r.status_code, "code": code})
    print(f"spoof {hdrs} -> {r.status_code} {code}")
out["header_bypass_blocked"] = all(x["status"] == 429 for x in out["header_bypass"])

# 3) light read burst (sequential, 25 reqs) to probe general limiter / stability
tok = login("<REDACTED_EMAIL>")
codes = []
t0 = time.monotonic()
for i in range(25):
    r = requests.get(f"{BASE}/reports?limit=5", headers=H(tok), timeout=20)
    codes.append(r.status_code)
dur = round(time.monotonic() - t0, 2)
out["read_burst"] = {"n": 25, "seconds": dur, "statuses": codes,
                     "any_429": any(c == 429 for c in codes), "all_200": all(c == 200 for c in codes)}
print("read burst 25 ->", "all_200" if all(c == 200 for c in codes) else codes, f"({dur}s)")

save("04_rate_limit.json", out)
