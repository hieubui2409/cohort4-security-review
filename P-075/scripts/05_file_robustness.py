#!/usr/bin/env python3
"""Battery 5 — File/image robustness on the upload surface.

Entry point is POST /photos/privacy-preview (the mandatory first step; the real /photos
upload requires a signed privacy ticket issued here). Feed hostile inputs and confirm each
one returns a safe 4xx with a clean JSON error (no 500, no stack/trace leak):
  - oversized (> 5 MB)
  - truncated / malformed image
  - PDF and ZIP disguised as .jpg (wrong magic)
  - decompression / pixel bomb (huge dimensions, tiny file)
  - path-traversal filename in the multipart part
  - bad mask geometry
Also: POST /photos with NO valid ticket must fail closed (not store, not 500).
"""
import sys, io, zipfile, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _common import BASE, H, login, save, body_snip
import requests
from PIL import Image

tok = login("<REDACTED_EMAIL>")
out = {"base": BASE, "cases": []}


def send(label, filename, content, mime="image/jpeg", extra=None, ticket_test=False, bytes_hint=None):
    files = {"file": (filename, content, mime)}
    data = extra or {}
    path = "/photos" if ticket_test else "/photos/privacy-preview"
    if ticket_test:
        data = {"purpose": "customer_report", "privacy_reviewed": "true", "privacy_ticket": "forged.deadbeef"}
    t0 = time.monotonic()
    r = requests.post(f"{BASE}{path}", headers=H(tok), files=files, data=data, timeout=60)
    ms = round((time.monotonic() - t0) * 1000)
    txt = body_snip(r, 300)
    leak = any(s in txt for s in ("Traceback", "File \"", "line ", "Exception", "sqlalchemy", "psycopg", "/app/"))
    rec = {"label": label, "path": path, "status": r.status_code, "ms": ms,
           "bytes": bytes_hint if bytes_hint is not None else len(content) if isinstance(content, (bytes, bytearray)) else None,
           "stack_leak": leak, "body": txt}
    out["cases"].append(rec)
    print(f"[{label}] {path} -> {r.status_code} ({ms}ms) leak={leak} :: {txt[:110]}")
    return r


# baseline: a valid small JPEG -> expect 200 (and a ticket in response)
buf = io.BytesIO(); Image.new("RGB", (640, 480), (123, 200, 90)).save(buf, "JPEG"); valid = buf.getvalue()
r = send("valid 640x480 jpeg (baseline)", "ok.jpg", valid)

# 1) oversized: 6 MB of random-ish bytes
import os
send("oversized 6MB", "big.jpg", os.urandom(6 * 1024 * 1024), bytes_hint=6 * 1024 * 1024)

# 2) truncated/malformed image (valid header + garbage)
send("truncated jpeg", "trunc.jpg", valid[:200] + b"\x00\xff" * 50)

# 3) PDF disguised as jpg
pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
send("PDF as .jpg", "doc.jpg", pdf, mime="image/jpeg")

# 4) ZIP disguised as jpg
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z:
    z.writestr("a.txt", "hello")
send("ZIP as .jpg", "arc.jpg", zb.getvalue(), mime="image/jpeg")

# 5) pixel bomb: 7000x7000 solid PNG (>20M px, tiny on disk)
buf = io.BytesIO(); Image.new("RGB", (7000, 7000), (0, 0, 0)).save(buf, "PNG"); bomb = buf.getvalue()
send("pixel bomb 7000x7000 png", "bomb.png", bomb, mime="image/png")

# 6) path-traversal filename (content is a valid jpeg so only the name is hostile)
send("traversal filename", "../../../../etc/passwd.jpg", valid)

# 7) bad mask geometry on a valid image
send("bad mask json", "ok.jpg", valid, extra={"masks": "[[0.9,0.9,0.1,0.1]]"})
send("too many masks", "ok.jpg", valid, extra={"masks": "[" + ",".join(["[0,0,0.1,0.1]"] * 40) + "]"})

# 8) upload with forged ticket -> must fail closed (422), never store
send("upload forged ticket", "ok.jpg", valid, ticket_test=True)

out["any_5xx"] = any(c["status"] >= 500 for c in out["cases"])
out["any_stack_leak"] = any(c["stack_leak"] for c in out["cases"])
print("any_5xx:", out["any_5xx"], "any_stack_leak:", out["any_stack_leak"])
save("05_file_robustness.json", out)
