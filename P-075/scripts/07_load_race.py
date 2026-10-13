#!/usr/bin/env python3
"""Battery 7 — Load/contention (read+write) and race / double-submit.

Safety: concurrency capped at 30 (project rail "burst <= 30"); the loop aborts on 3
consecutive 5xx. Every created record is labelled SECTEST- and its id is recorded for
cleanup (reports are closed by 08_cleanup.py).

A) READ load ramp on GET /reports at concurrency 5,10,20,30: p50/p95/p99, throughput, errors.
B) WRITE race, same Idempotency-Key, 10 concurrent POST /reports -> must dedup to 1 report.
C) WRITE race, DIFFERENT keys, same trip+category, 8 concurrent -> check_reportable advisory
   lock + with_for_update must allow exactly one 201 and reject the rest DUPLICATE_REPORT.
"""
import sys, time, statistics
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _common import BASE, H, login, save
import requests

tok = login("<REDACTED_EMAIL>")
HDR = H(tok)
out = {"base": BASE, "read_ramp": [], "race_same_key": {}, "race_diff_keys": {}, "created_report_ids": []}


def pct(xs, p):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(p / 100 * len(xs)))], 1)


def one_get():
    t0 = time.monotonic()
    try:
        r = requests.get(f"{BASE}/reports?limit=5", headers=HDR, timeout=30)
        return r.status_code, (time.monotonic() - t0) * 1000
    except Exception as e:
        return "ERR", (time.monotonic() - t0) * 1000


# A) read ramp
abort = False
for conc in (5, 10, 20, 30):
    if abort:
        break
    n = conc * 3  # ~3 waves at this concurrency
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=conc) as ex:
        res = list(ex.map(lambda _: one_get(), range(n)))
    wall = time.monotonic() - t0
    lat = [ms for _, ms in res]
    codes = [c for c, _ in res]
    n5xx = sum(1 for c in codes if isinstance(c, int) and c >= 500)
    rec = {"concurrency": conc, "requests": n, "wall_s": round(wall, 2),
           "throughput_rps": round(n / wall, 1),
           "p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99),
           "errors": sum(1 for c in codes if c == "ERR"), "n_5xx": n5xx,
           "status_set": sorted({str(c) for c in codes})}
    out["read_ramp"].append(rec)
    print(f"conc={conc:>2} rps={rec['throughput_rps']:>5} p50={rec['p50']} p95={rec['p95']} p99={rec['p99']} 5xx={n5xx} {rec['status_set']}")
    if n5xx >= 3:
        print("ABORT: >=3 5xx at concurrency", conc)
        abort = True

# B) race same idempotency key -> dedup
KEY = "sectest-race-samekey-01"
TRIP_B = "WF-20261009-1-2"
body_b = {"category_code": "other", "description": "SECTEST-race-same-key double-submit", "pledge": True, "trip_id": TRIP_B}


def post_same(_):
    r = requests.post(f"{BASE}/reports", headers=H(tok, **{"Idempotency-Key": KEY}), json=body_b, timeout=30)
    try:
        j = r.json()
    except Exception:
        j = {}
    return r.status_code, j.get("id") or j.get("error", {}).get("code")


with ThreadPoolExecutor(max_workers=10) as ex:
    rb = list(ex.map(post_same, range(10)))
ids_b = {v for s, v in rb if s == 201}
out["race_same_key"] = {"key": KEY, "trip": TRIP_B, "results": rb,
                        "unique_created": sorted(ids_b), "dedup_ok": len(ids_b) <= 1}
out["created_report_ids"] += [i for i in ids_b if i]
print("RACE same-key: 201 unique ids =", ids_b, "dedup_ok:", len(ids_b) <= 1)

# C) race different keys, same trip+category -> exactly one 201, rest DUPLICATE_REPORT
TRIP_C = "WF-20261009-1-3"
body_c = {"category_code": "other", "description": "SECTEST-race-diff-keys contention test", "pledge": True, "trip_id": TRIP_C}


def post_diff(i):
    r = requests.post(f"{BASE}/reports", headers=H(tok, **{"Idempotency-Key": f"sectest-diffkey-{i:02d}"}), json=body_c, timeout=30)
    try:
        j = r.json()
    except Exception:
        j = {}
    return r.status_code, j.get("id") or j.get("error", {}).get("code")


with ThreadPoolExecutor(max_workers=8) as ex:
    rc = list(ex.map(post_diff, range(8)))
created_c = [v for s, v in rc if s == 201]
dups = [v for s, v in rc if v == "DUPLICATE_REPORT"]
out["race_diff_keys"] = {"trip": TRIP_C, "results": rc, "created": created_c,
                         "n_created": len(created_c), "n_duplicate": len(dups),
                         "single_winner_ok": len(created_c) == 1}
out["created_report_ids"] += created_c
print("RACE diff-keys: created=", created_c, "duplicates=", len(dups), "single_winner_ok:", len(created_c) == 1)

save("07_load_race.json", out)
print("CREATED SECTEST report ids (for cleanup):", out["created_report_ids"])
