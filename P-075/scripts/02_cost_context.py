#!/usr/bin/env python3
"""Battery 1+2 — Chi phí/context: very long text into report description and chat.

Goal: confirm oversized payloads are rejected/bounded (not stored, not forwarded to an
LLM uncut), so an attacker cannot run up token cost or overflow context.
  - report description: pydantic max_length=3000
  - chat body: max_length=300
  - also records daily photo budget (120) enforcement path from code (not flooded live)
"""
import sys, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _common import BASE, H, login, save, body_snip
import requests

tok = login("<REDACTED_EMAIL>")
out = {"base": BASE, "cases": []}


def case(label, method, path, **kw):
    t0 = time.monotonic()
    r = requests.request(method, f"{BASE}{path}", timeout=60, **kw)
    ms = round((time.monotonic() - t0) * 1000)
    rec = {"label": label, "path": path, "status": r.status_code, "ms": ms, "body": body_snip(r, 240)}
    out["cases"].append(rec)
    print(f"[{label}] {method} {path} -> {r.status_code} ({ms} ms) req_bytes={kw.get('_bytes','?')}")
    return r


# description-preview accepts description up to 3000; send 200k chars -> expect 422 (bounded)
for n in (50_000, 200_000):
    payload = {"description": "A" * n, "private_mark": ""}
    r = requests.request("POST", f"{BASE}/description-preview", headers=H(tok),
                         json=payload, timeout=60)
    out["cases"].append({"label": f"description-preview {n} chars", "status": r.status_code,
                         "body": body_snip(r, 200), "req_bytes": n})
    print(f"[description-preview {n}] -> {r.status_code} {body_snip(r,120)}")

# report creation with 200k-char description -> expect 422 before any processing
big = {"category_code": "other", "description": "SECTEST-" + "B" * 200_000, "pledge": True,
       "trip_id": "T163"}
r = requests.post(f"{BASE}/reports", headers=H(tok, **{"Idempotency-Key": "sectest-bigdesc-001"}),
                  json=big, timeout=60)
out["cases"].append({"label": "POST /reports 200k desc", "status": r.status_code,
                     "body": body_snip(r, 240)})
print("POST /reports 200k desc ->", r.status_code, body_snip(r, 160))

# just-at-limit (3000) vs just-over (3001) to prove the boundary is enforced
for n in (3000, 3001):
    r = requests.post(f"{BASE}/description-preview", headers=H(tok),
                      json={"description": "C" * n}, timeout=30)
    out["cases"].append({"label": f"description-preview exactly {n}", "status": r.status_code,
                         "body": body_snip(r, 160)})
    print(f"[desc {n}] -> {r.status_code}")

# chat body length probe needs an open chat; we only probe validation on a bad id so the
# 300-char Field rule is exercised before ownership. Send 10k chars.
r = requests.post(f"{BASE}/reports/does-not-exist/chat", headers=H(tok),
                  json={"body": "D" * 10_000}, timeout=30)
out["cases"].append({"label": "chat 10k chars (validation)", "status": r.status_code,
                     "body": body_snip(r, 200)})
print("chat 10k ->", r.status_code, body_snip(r, 120))
# valid-length chat on nonexistent report (ownership/404 path, proves 300 passes validation)
r = requests.post(f"{BASE}/reports/does-not-exist/chat", headers=H(tok),
                  json={"body": "E" * 300}, timeout=30)
out["cases"].append({"label": "chat 300 chars (validation ok)", "status": r.status_code,
                     "body": body_snip(r, 200)})
print("chat 300 ->", r.status_code, body_snip(r, 120))

save("02_cost_context.json", out)
