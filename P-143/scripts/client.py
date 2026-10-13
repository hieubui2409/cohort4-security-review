"""Shared stdlib-only HTTP helper for P-143 dynamic security tests.
Run callers with: python -I <script> <base_url> ...
No imports from the repo. Uses urllib only."""
import json, time, urllib.request, urllib.error, ssl

def req(method, url, token=None, body=None, headers=None, raw=None, timeout=30):
    h = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    if raw is not None:
        data = raw
    if token: h["Authorization"] = "Bearer " + token
    if headers: h.update(headers)
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            b = resp.read()
            dt = time.perf_counter() - t0
            return resp.status, dict(resp.headers), b, dt
    except urllib.error.HTTPError as e:
        b = e.read()
        dt = time.perf_counter() - t0
        return e.code, dict(e.headers), b, dt
    except Exception as e:
        dt = time.perf_counter() - t0
        return -1, {}, str(e).encode(), dt

def jbody(b):
    try: return json.loads(b)
    except Exception: return None

def login(base, email, password):
    s, h, b, dt = req("POST", base + "/api/v1/auth/login", body={"email": email, "password": password})
    j = jbody(b)
    tok = (j or {}).get("access_token")
    return tok, s, j
