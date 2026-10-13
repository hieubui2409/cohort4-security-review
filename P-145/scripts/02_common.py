"""Shared helpers for P-145 extended battery (02_*). Dynamic API tests via requests.Session.

Auth: cookie httpOnly set by POST /auth/login (no token in body). We keep the Session cookie jar.
"""
import os, sys, json, time, requests

BASE = os.environ.get("P145_BASE", "https://<REDACTED_DEPLOY>/api/v1")
HR_EMAIL = "<REDACTED_EMAIL>"
HR_PASS = "<REDACTED_PASSWORD>"
TIMEOUT = 60
EVID = os.path.join(os.path.dirname(__file__), "..", "evidences")

def hr_session():
    s = requests.Session()
    s.headers["User-Agent"] = "P145-sectest/02"
    r = s.post(f"{BASE}/auth/login", json={"email": HR_EMAIL, "password": HR_PASS}, timeout=TIMEOUT)
    r.raise_for_status()
    assert "access_token" in s.cookies, "no cookie set"
    return s

def save(name, obj):
    path = os.path.join(EVID, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    print(f"[saved] {path}")

def preview(s, filename, data, ctype="application/octet-stream"):
    """POST /hr/knowledge/preview. Returns (status, elapsed_s, json_or_text)."""
    t = time.time()
    r = s.post(f"{BASE}/hr/knowledge/preview",
               files={"file": (filename, data, ctype)}, timeout=TIMEOUT)
    el = round(time.time() - t, 3)
    try: body = r.json()
    except Exception: body = r.text[:600]
    return r.status_code, el, body
