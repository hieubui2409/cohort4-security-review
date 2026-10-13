#!/usr/bin/env python3
"""
P-075 — Quét phân quyền động (xác nhận cách ly, KHÔNG phá huỷ):
  - Lấy report của customer khác / driver khác (IDOR qua {id})
  - Đọc secret-answers hồ sơ không thuộc mình
  - customer/driver gọi endpoint staff (/staff/queue)
Kỳ vọng hệ thống tốt: 403/404.
"""
import json, requests
BASE = "https://<REDACTED_DEPLOY>/api/v2"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-075/evidences"
creds = json.load(open("/home/hieubt15/Documents/demo-review-cohort4/handoff/T-075/demo-credentials.json"))

def login(email):
    r = requests.post(f"{BASE}/auth/login", json={"email": email, "password": creds[email]}, timeout=25)
    return r.json()["access_token"]

def H(t): return {"Authorization": f"Bearer {t}"}

tok = {e: login(e) for e in ["<REDACTED_EMAIL>", "<REDACTED_EMAIL>", "<REDACTED_EMAIL>", "<REDACTED_EMAIL>"]}
res = {"base": BASE, "probes": []}

def listreports(t):
    r = requests.get(f"{BASE}/reports?limit=50", headers=H(t), timeout=25)
    return r.json().get("items", []) if r.status_code == 200 else []

# thu thập id hồ sơ của từng bên để chéo
ids = {}
for e in ["<REDACTED_EMAIL>", "<REDACTED_EMAIL>", "<REDACTED_EMAIL>"]:
    its = listreports(tok[e])
    ids[e] = [i.get("id") for i in its if i.get("id")]
    res["probes"].append({"who": e, "own_reports_count": len(ids[e]), "sample": ids[e][:3]})
    print(f"{e}: {len(ids[e])} reports own")

def probe(label, method, path, token):
    r = requests.request(method, f"{BASE}{path}", headers=H(token), timeout=25)
    res["probes"].append({"label": label, "path": path, "status": r.status_code,
                          "body": (r.text[:160])})
    print(f"[{label}] {method} {path} -> {r.status_code}")
    return r.status_code

# chọn 1 report của khach1 để khach2/taixe1 thử truy cập chéo
victim = ids.get("<REDACTED_EMAIL>") or ids.get("<REDACTED_EMAIL>")
if victim:
    rid = victim[0]
    probe("IDOR report: khach2 xem report khach1", "GET", f"/reports/{rid}", tok["<REDACTED_EMAIL>"])
    probe("IDOR secret-answers: khach2", "GET", f"/reports/{rid}/secret-answers", tok["<REDACTED_EMAIL>"])
    probe("IDOR audit: khach2", "GET", f"/reports/{rid}/audit", tok["<REDACTED_EMAIL>"])
else:
    res["note_no_victim_report"] = True
    print("khach1/khach2 chưa có report để test IDOR báo cáo")

# BFLA: customer & driver gọi endpoint staff
probe("BFLA staff/queue bằng customer", "GET", "/staff/queue", tok["<REDACTED_EMAIL>"])
probe("BFLA staff/queue bằng driver", "GET", "/staff/queue", tok["<REDACTED_EMAIL>"])
# truy cập không token
r = requests.get(f"{BASE}/reports", timeout=25); print("no-token /reports ->", r.status_code)
res["no_token_reports"] = r.status_code

json.dump(res, open(f"{OUT}/01_authz_sweep.json", "w"), ensure_ascii=False, indent=2)
print("saved ->", f"{OUT}/01_authz_sweep.json")
