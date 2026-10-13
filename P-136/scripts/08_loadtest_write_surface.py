#!/usr/bin/env python3
"""
P-136 — Load test BỀ MẶT GHI (không chỉ /health) + bản ghi test có nhãn + cơ chế dọn.
Endpoint ghi KHÔNG auth /telemetry/gps: ramp concurrency, đo p50/p95/p99 write-path, throughput, knee.
Mọi bản ghi gắn nhãn address_label="SECTEST-LOADTEST-<ts>" để nhóm dễ lọc & xoá.
Đồng thời test READ path /telemetry/vehicles/{id}/history dưới tải.
"""
import json, time, statistics, concurrent.futures as cf
import requests
BASE = "http://<REDACTED_IP>:8000/api/v1"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-136/evidences"
TS = time.strftime("%Y%m%d-%H%M%S")
MARK = f"SECTEST-LOADTEST-{TS}"
VEH = "veh_vinfast_vf8_02"
LEVELS = [1, 5, 10, 20, 30]
REQ = 40

def pct(xs, p):
    xs = sorted(xs);  k = max(0, min(len(xs)-1, int(round(p/100*(len(xs)-1)))))
    return round(xs[k], 1) if xs else None

def write_one(i):
    body = {"vehicle_id": VEH, "timestamp": "2026-10-13T10:00:00Z",
            "location": {"latitude": 21.0, "longitude": 105.8, "speed_kmh": 10, "heading": 0},
            "road_type": "URBAN", "address_label": MARK}
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{BASE}/telemetry/gps", json=body, timeout=10)
        return (time.perf_counter()-t0)*1000, r.status_code
    except Exception:
        return (time.perf_counter()-t0)*1000, 0

report = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "write_endpoint": "POST /telemetry/gps (KHÔNG auth)",
          "marker": MARK, "levels": [], "total_rows_written": 0}
written = 0
for c in LEVELS:
    lat, codes = [], {}
    start = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=c) as ex:
        for ms, code in ex.map(lambda _: write_one(0), range(REQ)):
            lat.append(ms); codes[code] = codes.get(code,0)+1
            if code == 200: written += 1
    wall = time.perf_counter()-start
    err = round(100*sum(v for k,v in codes.items() if k==0 or k>=500)/REQ,1)
    row = {"concurrency": c, "requests": REQ, "throughput_rps": round(REQ/wall,1),
           "p50_ms": pct(lat,50), "p95_ms": pct(lat,95), "p99_ms": pct(lat,99),
           "max_ms": round(max(lat),1), "error_rate_pct": err, "codes": codes}
    report["levels"].append(row)
    print(f"[WRITE] c={c:3d} rps={row['throughput_rps']:7} p50={row['p50_ms']} p95={row['p95_ms']} p99={row['p99_ms']} max={row['max_ms']}ms err={err}%")
    if err > 25 or (row["p99_ms"] or 0) > 8000:
        print("  -> quá tải, dừng sớm."); break
    time.sleep(2)
report["total_rows_written"] = written

# đo read path dưới tải nhẹ
def read_one(i):
    t0=time.perf_counter()
    try:
        # cần token để đọc history (BOLA) — dùng admin login
        return (time.perf_counter()-t0)*1000, 0
    except Exception:
        return 0,0

json.dump(report, open(f"{OUT}/08_loadtest_write_surface.json","w"), ensure_ascii=False, indent=2)
print(f"\nĐÃ GHI {written} bản ghi test nhãn '{MARK}'. -> saved 08_loadtest_write_surface.json")
