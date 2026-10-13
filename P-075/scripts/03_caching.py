#!/usr/bin/env python3
"""Battery 3 — Caching / repeat-request cost.

Two angles:
  (a) Request-level idempotency: POST with the same Idempotency-Key returns the stored
      response and does NOT create a second record (replay() in v2_common.py).
  (b) VLM comparison cache: matching.py keys each model comparison by _cache_key and reuses
      a prior MODEL_SOURCES answer (cache_hit=True) instead of re-calling the provider; a
      daily call/budget guard (budget_state) bounds spend. Verified by source review here;
      live VLM runs in mock mode so no provider call is made at all.

Live demonstration uses /description-preview (no side effects): repeat identical input and
confirm identical, cheap output (local filtering, never re-sent to an LLM).
"""
import sys, time, statistics
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _common import BASE, H, login, save, body_snip
import requests

tok = login("<REDACTED_EMAIL>")
out = {"base": BASE, "determinism": [], "idempotency": {}}

payload = {"description": "balo màu đen có móc khóa cá heo, một vết xước ở quai", "private_mark": ""}
lat = []
first = None
for i in range(8):
    t0 = time.monotonic()
    r = requests.post(f"{BASE}/description-preview", headers=H(tok), json=payload, timeout=30)
    ms = round((time.monotonic() - t0) * 1000)
    lat.append(ms)
    j = r.json()
    if first is None:
        first = j
    out["determinism"].append({"i": i, "status": r.status_code, "ms": ms,
                               "same_as_first": j == first, "model_description": j.get("model_description")})
print("description-preview repeated x8 -> all identical:", all(x["same_as_first"] for x in out["determinism"]))
print("latency p50/p95:", round(statistics.median(lat)), round(sorted(lat)[int(0.95*len(lat))-1]))
out["latency_ms"] = {"p50": statistics.median(lat), "min": min(lat), "max": max(lat), "samples": lat}

# (a) idempotency replay on a real (labelled) report creation
key = "sectest-idem-cache-001"
rp = {"category_code": "other", "description": "SECTEST-caching-idempotency-demo item", "pledge": True,
      "trip_id": "T163"}
ids = []
for i in range(3):
    r = requests.post(f"{BASE}/reports", headers=H(tok, **{"Idempotency-Key": key}), json=rp, timeout=30)
    j = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    ids.append({"i": i, "status": r.status_code, "report_id": j.get("id"), "revision": j.get("revision")})
    print(f"replay {i}: {r.status_code} id={j.get('id')}")
unique = {x["report_id"] for x in ids if x["report_id"]}
out["idempotency"] = {"key": key, "calls": ids, "unique_report_ids": sorted(unique),
                      "dedup_ok": len(unique) <= 1}
out["created_report_ids"] = sorted(unique)
print("idempotency dedup_ok:", len(unique) <= 1, "created:", sorted(unique))

save("03_caching.json", out)
