#!/usr/bin/env python3
"""
P-123 GreenCar — sweep phân quyền động (xác nhận cách ly):
  - list cases theo từng role
  - customer thử đọc case/evidence không thuộc mình (IDOR) -> kỳ vọng 404
  - customer/driver gọi endpoint CSKH (/cskh-tasks) (BFLA) -> kỳ vọng 403/404
  - không token -> 401
Tài khoản: customer01/Customer@123456, driver01/Driver@123456, cskh01/CSKH@12345678
"""
import json, requests, time
B = "https://<REDACTED_DEPLOY>/api/v1"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-123/evidences"

def login(u, p, role):
    r = requests.post(f"{B}/auth/login", json={"username": u, "password": p, "role": role}, timeout=40)
    return r.json()

cu = login("customer01", "Customer@123456", "customer")
dr = login("driver01", "Driver@123456", "driver")
cs = login("cskh01", "CSKH@12345678", "cskh_agent")
def H(d): return {"Authorization": f"Bearer {d['access_token']}"}
out = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "base": B, "probes": []}

def probe(label, method, path, headers=None, **kw):
    r = requests.request(method, f"{B}{path}", headers=headers or {}, timeout=40, **kw)
    out["probes"].append({"label": label, "path": path, "status": r.status_code, "body": r.text[:150]})
    print(f"[{label}] {method} {path} -> {r.status_code} {r.text[:80]}")
    return r

# list cases per role
cases = {}
for name, d in [("customer", cu), ("driver", dr), ("cskh", cs)]:
    r = probe(f"list cases {name}", "GET", "/cases", H(d))
    try:
        items = r.json(); cases[name] = [c.get("id") for c in (items if isinstance(items, list) else items.get("items", []))]
    except Exception:
        cases[name] = []
out["cases_per_role"] = {k: len(v) for k, v in cases.items()}

# CSKH thấy mọi case -> lấy 1 case id để customer/driver thử IDOR
all_ids = cases.get("cskh") or []
victim = None
cust_ids = set(cases.get("customer") or [])
for cid in all_ids:
    if cid not in cust_ids:
        victim = cid; break
out["victim_case_for_idor"] = victim
if victim:
    probe("IDOR customer GET case khác", "GET", f"/cases/{victim}", H(cu))
    probe("IDOR customer GET customer-evidence khác", "GET", f"/cases/{victim}/customer-evidence", H(cu))
    probe("IDOR customer GET gps-history khác", "GET", f"/cases/{victim}/gps-history", H(cu))
    probe("IDOR driver GET case khác", "GET", f"/cases/{victim}", H(dr))

# BFLA: customer/driver gọi endpoint CSKH
probe("BFLA customer GET /cskh-tasks", "GET", "/cskh-tasks", H(cu))
probe("BFLA driver GET /cskh-tasks", "GET", "/cskh-tasks", H(dr))
# unauth
probe("no-token GET /cases", "GET", "/cases")

json.dump(out, open(f"{OUT}/01_authz_sweep.json", "w"), ensure_ascii=False, indent=2)
print("saved ->", f"{OUT}/01_authz_sweep.json")
