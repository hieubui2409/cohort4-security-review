"""P-143 dyn test driver. stdlib only; run with: python3 -I drive.py <base> ...
No repo imports. Uploads files, polls status, prints JSON."""
import json, sys, time, uuid, urllib.request, urllib.error

BASE = sys.argv[1].rstrip("/")

def req(method, path, token=None, body=None, multipart=None, timeout=60):
    url = BASE + path
    h = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    if multipart is not None:
        boundary = "----sectest" + uuid.uuid4().hex
        parts = []
        for field, fname, ctype, content in multipart:
            parts.append(("--" + boundary).encode())
            parts.append(('Content-Disposition: form-data; name="%s"; filename="%s"' % (field, fname)).encode())
            parts.append(("Content-Type: " + ctype).encode())
            parts.append(b"")
            parts.append(content)
        parts.append(("--" + boundary + "--").encode()); parts.append(b"")
        data = b"\r\n".join(parts)
        h["Content-Type"] = "multipart/form-data; boundary=" + boundary
    if token: h["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def jl(b):
    try: return json.loads(b)
    except Exception: return b.decode("utf-8", "replace")[:400]

def login(email, pw):
    s, b = req("POST", "/api/v1/auth/login", body={"email": email, "password": pw})
    return (jl(b) or {}).get("access_token"), s, jl(b)

if __name__ == "__main__":
    cmd = sys.argv[2]
    if cmd == "login":
        tok, s, j = login(sys.argv[3], sys.argv[4]); print(s, tok or j)
    elif cmd == "upload":
        tok = sys.argv[3]; fpath = sys.argv[4]; fname = sys.argv[5]; ctype = sys.argv[6]
        with open(fpath, "rb") as f: content = f.read()
        s, b = req("POST", "/api/v1/invoices/upload", token=tok, multipart=[("files", fname, ctype, content)])
        print(s, json.dumps(jl(b), ensure_ascii=False))

    elif cmd == "uploadfield":
        tok = sys.argv[3]; field=sys.argv[4]; fpath = sys.argv[5]; fname = sys.argv[6]; ctype = sys.argv[7]; path=sys.argv[8]
        with open(fpath, "rb") as f: content = f.read()
        s, b = req("POST", path, token=tok, multipart=[(field, fname, ctype, content)])
        print(s, json.dumps(jl(b), ensure_ascii=False))
    elif cmd == "get":
        tok = sys.argv[3]; path = sys.argv[4]
        s, b = req("GET", path, token=tok)
        print(s, json.dumps(jl(b), ensure_ascii=False))
    elif cmd == "post":
        tok = sys.argv[3]; path = sys.argv[4]; body = json.loads(sys.argv[5]) if len(sys.argv)>5 else None
        s, b = req("POST", path, token=tok, body=body)
        print(s, json.dumps(jl(b), ensure_ascii=False))
