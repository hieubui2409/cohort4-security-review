#!/usr/bin/env python3
"""P-145 e2e Phase 1: tạo intake batch 1 nhân viên test + poll xem pipeline LLM có chạy không."""
import io, time, json, requests
from openpyxl import Workbook
B = "https://<REDACTED_DEPLOY>/api/v1"
s = requests.Session()
r = s.post(f"{B}/auth/login", json={"email":"<REDACTED_EMAIL>","password":"<REDACTED_PASSWORD>"}, timeout=30)
print("HR login:", r.status_code, "cookies:", list(s.cookies.keys()))
tok = (r.json().get("access_token") or r.json().get("token")) if r.ok else None
H = {"Authorization": f"Bearer {tok}"} if tok else {}

# roster 1 dòng — nhân viên test gắn nhãn rõ (dễ dọn)
wb = Workbook(); ws = wb.active
ws.append(["Họ tên","Email cá nhân","SĐT","Vị trí","Phòng ban","Chi nhánh","Loại HĐ","Ngày bắt đầu","Ca làm","Email quản lý"])
ws.append(["SECTEST Probe Nhan","<REDACTED_EMAIL>","0900111222","Điều dưỡng","Khoa Nội","CS1","Thử việc","2026-10-20","Hành chính","sim-manager-noi@bx.example.com"])
buf = io.BytesIO(); wb.save(buf); buf.seek(0)

files = {"roster": ("sectest_roster.xlsx", buf.read(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
r = s.post(f"{B}/hr/intake-batches", headers=H, files=files, timeout=60)
print("create batch:", r.status_code, r.text[:200])
if not r.ok: raise SystemExit("create batch failed")
bid = r.json().get("batch_id")
print("batch_id:", bid)

for i in range(40):  # ~120s
    time.sleep(3)
    g = s.get(f"{B}/hr/intake-batches/{bid}", headers=H, timeout=30)
    if not g.ok:
        print(" poll", i, g.status_code, g.text[:120]); continue
    j = g.json()
    items = j.get("items") or j.get("rows") or []
    sts = [(it.get("status"), (it.get("profile") or {}).get("full_name") if isinstance(it.get("profile"),dict) else None) for it in items]
    print(f" poll {i:2d} batch_status={j.get('status')} items={sts}")
    if items and all((it.get("status") in ("NEEDS_REVIEW","CREATED","REJECTED","needs_review","created","rejected")) for it in items):
        print("=> pipeline xong. batch dump:"); print(json.dumps(j, ensure_ascii=False)[:1500]); break
else:
    print("=> TIMEOUT: pipeline chưa tới trạng thái commit được (LLM deploy có thể không chạy)")
