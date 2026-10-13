#!/usr/bin/env python3
"""
P-047 — Load read+write có kiểm soát trên bề mặt thật (không tạo bản ghi rác).
READ:  GET /residents/R001/progress
WRITE: POST /residents/R001/checklist/rebuild  (idempotent — dựng lại checklist, không sinh bản ghi mới)
Ramp concurrency, đo p50/p95/p99, throughput, knee. Burst ngắn, dừng sớm nếu quá tải.
"""
import json, time, concurrent.futures as cf
import requests
B = "https://<REDACTED_DEPLOY>/api/v1"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-047/evidences"
tok = requests.post(f"{B}/auth/login", json={"username": "user", "password": "<REDACTED_PASSWORD>"}, timeout=25).json()["access_token"]
H = {"Authorization": f"Bearer {tok}"}
LEVELS = [1, 5, 10, 20]
REQ = 30

def pct(xs, p):
    xs = sorted(xs); k = max(0, min(len(xs)-1, int(round(p/100*(len(xs)-1))))); return round(xs[k], 1) if xs else None

def call(kind):
    t0 = time.perf_counter()
    try:
        if kind == "read":
            r = requests.get(f"{B}/residents/R001/progress", headers=H, timeout=15)
        else:
            r = requests.post(f"{B}/residents/R001/checklist/rebuild", headers=H, timeout=15)
        return (time.perf_counter()-t0)*1000, r.status_code
    except Exception:
        return (time.perf_counter()-t0)*1000, 0

def ramp(kind):
    rows = []
    for c in LEVELS:
        lat, codes = [], {}
        start = time.perf_counter()
        with cf.ThreadPoolExecutor(max_workers=c) as ex:
            for ms, sc in ex.map(lambda _: call(kind), range(REQ)):
                lat.append(ms); codes[sc] = codes.get(sc, 0)+1
        wall = time.perf_counter()-start
        err = round(100*sum(v for k,v in codes.items() if k==0 or k>=500)/REQ, 1)
        row = {"concurrency": c, "throughput_rps": round(REQ/wall,1), "p50_ms": pct(lat,50),
               "p95_ms": pct(lat,95), "p99_ms": pct(lat,99), "error_rate_pct": err, "codes": codes}
        rows.append(row)
        print(f"[{kind}] c={c:2d} rps={row['throughput_rps']} p50={row['p50_ms']} p95={row['p95_ms']} p99={row['p99_ms']} err={err}% {codes}")
        if err > 25 or (row["p99_ms"] or 0) > 8000:
            print("  dừng sớm (quá tải)"); break
        time.sleep(1.5)
    return rows

out = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "read": ramp("read"), "write_idempotent": ramp("write"),
       "note":"WRITE dùng checklist/rebuild (idempotent) nên không để lại bản ghi rác; không cần dọn."}
json.dump(out, open(f"{OUT}/06_load_read_write.json","w"), ensure_ascii=False, indent=2)
print("saved -> 06_load_read_write.json")
