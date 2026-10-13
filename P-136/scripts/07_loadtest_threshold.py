#!/usr/bin/env python3
"""
P-136 — Load test CÓ KIỂM SOÁT tìm ngưỡng + p50/p95/p99.
Dùng GET /health (read-only, KHÔNG bẩn dữ liệu) để đo năng lực máy chủ.
Ramp concurrency theo nấc, mỗi nấc gửi số request giới hạn, dừng sớm nếu error_rate cao.
Ghi chú: endpoint GHI không auth (/telemetry/gps) KHÔNG rate-limit -> cùng mức tải này sẽ
khuếch đại thành ghi DB vô giới hạn (thiệt hại thực lớn hơn con số đo read-only ở đây).
"""
import json, time, statistics, concurrent.futures as cf
import requests
BASE = "http://<REDACTED_IP>:8000"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-136/evidences"
URL = f"{BASE}/health"
LEVELS = [1, 5, 10, 20, 35, 50]
REQ_PER_LEVEL = 60

def one():
    t0 = time.perf_counter()
    try:
        r = requests.get(URL, timeout=10)
        return (time.perf_counter() - t0) * 1000, r.status_code
    except Exception:
        return (time.perf_counter() - t0) * 1000, 0

def pct(xs, p):
    xs = sorted(xs)
    if not xs: return None
    k = max(0, min(len(xs) - 1, int(round((p / 100) * (len(xs) - 1)))))
    return round(xs[k], 1)

report = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "target": URL, "levels": []}
knee = None
for c in LEVELS:
    lat, codes = [], {}
    start = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=c) as ex:
        for ms, code in ex.map(lambda _: one(), range(REQ_PER_LEVEL)):
            lat.append(ms); codes[code] = codes.get(code, 0) + 1
    wall = time.perf_counter() - start
    errors = sum(v for k, v in codes.items() if k == 0 or k >= 500)
    err_rate = round(100 * errors / REQ_PER_LEVEL, 1)
    row = {"concurrency": c, "requests": REQ_PER_LEVEL,
           "throughput_rps": round(REQ_PER_LEVEL / wall, 1),
           "p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99),
           "max_ms": round(max(lat), 1), "error_rate_pct": err_rate, "status_codes": codes}
    report["levels"].append(row)
    print(f"c={c:3d} rps={row['throughput_rps']:7} p50={row['p50_ms']}ms p95={row['p95_ms']}ms "
          f"p99={row['p99_ms']}ms max={row['max_ms']}ms err={err_rate}%")
    if knee is None and (err_rate > 5 or (row["p95_ms"] or 0) > 3000):
        knee = c
    # dừng sớm nếu quá tải rõ để tránh outage
    if err_rate > 25 or (row["p99_ms"] or 0) > 8000:
        print("  -> dấu hiệu quá tải, DỪNG ramp sớm.")
        break
    time.sleep(2)  # để server hồi giữa các nấc

report["knee_concurrency"] = knee
report["note"] = ("Đo trên /health (read-only). Endpoint ghi không auth /telemetry/gps không rate-limit "
                  "=> cùng concurrency này biến thành ghi DB vô giới hạn: cạn connection pool, phình bảng, "
                  "ảnh hưởng mọi người dùng. Thiệt hại thực tế > số đo read-only.")
json.dump(report, open(f"{OUT}/07_loadtest_threshold.json", "w"), ensure_ascii=False, indent=2)
print("knee ~", knee, "-> saved 07_loadtest_threshold.json")
