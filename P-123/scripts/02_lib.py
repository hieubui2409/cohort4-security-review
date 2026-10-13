"""Shared helpers for P-123 extended dynamic battery (02_*). Bearer auth (CSRF-exempt)."""
import base64, io, json, time, httpx

BASE = "https://<REDACTED_DEPLOY>/api/v1"
MARK = "SECTEST-"
CREDS = {
    "customer": ("customer01", "Customer@123456", "customer"),
    "driver":   ("driver01",   "Driver@123456",   "driver"),
    "cskh":     ("cskh01",      "CSKH@12345678",   "cskh_agent"),
}

def login(role, client=None):
    u, p, r = CREDS[role]
    c = client or httpx
    rr = c.post(f"{BASE}/auth/login", json={"username": u, "password": p, "role": r}, timeout=60)
    rr.raise_for_status()
    return rr.json()["access_token"]

def hdr(token):
    return {"Authorization": f"Bearer {token}"}

def tiny_png(w=1, h=1):
    """Return raw bytes of a minimal solid PNG w*h using Pillow if present else a 1x1."""
    try:
        from PIL import Image
        buf = io.BytesIO()
        Image.new("RGB", (w, h), (10, 120, 60)).save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
        )

def b64(data):
    return base64.b64encode(data).decode()

def save_evidence(name, obj):
    import os
    d = os.path.join(os.path.dirname(__file__), "..", "evidences")
    path = os.path.join(d, name)
    with open(path, "w") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
    return path
