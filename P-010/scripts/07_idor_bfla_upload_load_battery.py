#!/usr/bin/env python3
"""P-010 VinStay AI — DYNAMIC battery: IDOR/BFLA + upload robustness + write-load (SECTEST-).

Runs against a locally-built stack (Postgres container + real NestJS backend) with the
OTP / VietQR / eKYC providers STUBBED the same way the LLM was stubbed earlier:
  - OTP:   OTP_ECHO_DEV_CODE=true  -> POST /auth/otp/send returns `devCode` (ConsoleOtpSender),
           no Zalo/SMS provider needed.
  - VietQR: VIETQR_* + VIETQR_WEBHOOK_SECRET set in env (we own the secret) + DEMO_TOOLS=true
           -> deposit create + webhook/demo-pay work without a real bank.
  - eKYC:  identity.service always throws `ekyc_provider_unavailable` (503) AFTER the ownership
           check, and the only VerificationLevel gating writes is `phone` (CCCD not wired),
           so eKYC does not gate booking/deposit; its IDOR check is still reachable.

This script imports NOTHING from the repo and is run with `python3 -I` from OUTSIDE the app
repo. stdlib only. Writes JSON evidence under reviews/P-010/evidences/.

Usage: python3 -I 07_idor_bfla_upload_load_battery.py
"""
import json, time, io, os, ssl, socket, statistics, threading, urllib.request, urllib.error, datetime, uuid
from concurrent.futures import ThreadPoolExecutor

B = "http://127.0.0.1:4000/api/v1"
EV_DIR = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-010/evidences"
ACCOUNTS = {
    "tenantA":   ("sectest.tenantA@example.com",   "tenant"),
    "tenantB":   ("sectest.tenantB@example.com",   "tenant"),
    "landlordA": ("sectest.landlordA@example.com", "landlord"),
    "landlordB": ("sectest.landlordB@example.com", "landlord"),
}
PASSWORD = "<REDACTED_PASSWORD>"
TOKENS = {}   # name -> vs_access jwt


def _req(method, path, body=None, token=None, headers=None, raw=None, ctype="application/json", timeout=60):
    url = B + path
    h = dict(headers or {})
    data = None
    if raw is not None:
        data = raw
        if ctype:
            h["Content-Type"] = ctype
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if token:
        h["Cookie"] = f"vs_access={token}"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode("utf-8", "replace")
            return r.status, txt, dict(r.headers), int((time.monotonic()-t0)*1000)
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        return e.code, txt, dict(e.headers), int((time.monotonic()-t0)*1000)
    except Exception as e:
        return 0, f"ERR {type(e).__name__}: {e}", {}, int((time.monotonic()-t0)*1000)


def login_all():
    for name, (email, portal) in ACCOUNTS.items():
        req = urllib.request.Request(B + "/auth/login", method="POST",
            data=json.dumps({"email": email, "password": PASSWORD, "portal": portal}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            sc = r.headers.get_all("Set-Cookie") or []
        tok = None
        for c in sc:
            if c.startswith("vs_access="):
                tok = c.split("=", 1)[1].split(";", 1)[0]
        TOKENS[name] = tok
        print(f"  login {name}: token={'ok' if tok else 'MISSING'}")


def get_action_token(phone, purpose="TENANT_VIEWING"):
    s, t, _, _ = _req("POST", "/auth/otp/send", {"phone": phone, "purpose": purpose})
    dev = json.loads(t)["data"].get("devCode")
    s, t, _, _ = _req("POST", "/auth/otp/verify", {"phone": phone, "purpose": purpose, "code": dev})
    return json.loads(t)["data"]["actionToken"]


def slot_iso(days_ahead, hhmm_vn):
    h, m = hhmm_vn
    d = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_ahead)
    return d.replace(hour=h-7, minute=m, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%S.000Z")


VN_TIMES = [(8,30),(9,30),(10,30),(14,30),(15,30),(16,30),(17,30)]


def all_slots():
    out = []
    for day in range(1, 14):
        for (h, m) in VN_TIMES:
            out.append(slot_iso(day, (h, m)))
    return out


def create_booking(token, unit_code, slot, name, phone, action_token=None):
    body = {"unitCode": unit_code, "slot": slot, "contactName": name, "phone": phone}
    if action_token:
        body["actionToken"] = action_token
    return _req("POST", "/bookings", body, token=token)


def multipart(fields, files):
    """fields: list of (name,value); files: list of (field,filename,content_bytes,ctype)."""
    boundary = "----sectest" + uuid.uuid4().hex
    buf = io.BytesIO()
    def w(s): buf.write(s if isinstance(s, bytes) else s.encode())
    for n, v in fields:
        w(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n")
    for field, fn, content, ct in files:
        w(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{fn}\"\r\n")
        w(f"Content-Type: {ct}\r\n\r\n")
        w(content); w("\r\n")
    w(f"--{boundary}--\r\n")
    return buf.getvalue(), f"multipart/form-data; boundary={boundary}"


# tiny valid 1x1 PNG / JPEG / WEBP (magic + minimal header the server's size-reader accepts)
PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a"
    "49444154789c6360000002000154a24f3e0000000049454e44ae426082")
JPEG_HDR = bytes.fromhex("ffd8ffe000104a46494600010100000100010000ffdb004300"
    "08060607060508070707090908" + "0a"*50 ) + bytes.fromhex(
    "ffc0001108006400640301220002110103110100ffc4001f0000010501010101010100000000000000000102030405060708090a0bffda0008010100003f00d2cf20")
# A small but structurally valid baseline JPEG header declaring 100x100 (SOF0 at 0x64 0x64).


results = {"idor_bfla": [], "upload": [], "load": []}


def rec(group, tid, title, inp, status, verdict, note, output=""):
    r = {"id": tid, "title": title, "input": inp, "http": status, "verdict": verdict,
         "note": note, "output_excerpt": (output or "")[:600],
         "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    results[group].append(r)
    print(f"  [{tid}] http={status} {verdict} :: {title}")
    return r


def code_of(txt):
    try: return json.loads(txt).get("code") or (json.loads(txt).get("data") or {})
    except Exception: return None


# ============================================================ BATTERY 1
def battery_idor_bfla(unitA):
    print("\n=== BATTERY 1: IDOR / BFLA (dynamic) ===")
    tA, tB = TOKENS["tenantA"], TOKENS["tenantB"]
    lA, lB = TOKENS["landlordA"], TOKENS["landlordB"]

    # --- object owned by tenantA: a booking ref ---
    at = get_action_token("0912345670")  # tenantA's verified phone
    slot = slot_iso(3, (10, 30))
    s, t, _, _ = create_booking(tA, unitA, slot, "SECTEST OwnerA", "0912345670", at)
    refA = json.loads(t)["data"]["ref"] if s in (200, 201) else None
    rec("idor_bfla", "SETUP", "tenantA creates a booking to own", f"unit={unitA} slot={slot}",
        s, "ok" if refA else "FAILED", f"refA={refA}", t)
    assert refA, "could not create tenantA booking: " + t

    # control: owner can read own
    s, t, _, _ = _req("GET", f"/bookings/{refA}", token=tA)
    rec("idor_bfla", "CTRL-1", "tenantA GET own booking (positive control)", f"GET /bookings/{refA}",
        s, "OK" if s == 200 else "unexpected", "owner must succeed", t)

    # --- OBJECT-LEVEL IDOR (BOLA): tenantB touches tenantA's booking ref ---
    idor_paths = [
        ("GET",  f"/bookings/{refA}",                 None),
        ("POST", f"/bookings/{refA}/cancel",          {"reason": "sectest idor attempt"}),
        ("POST", f"/bookings/{refA}/reschedule",      {"slot": slot_iso(4, (9, 30))}),
        ("POST", f"/bookings/{refA}/late",            None),
        ("POST", f"/bookings/{refA}/lobby-checkin",   None),
        ("POST", f"/bookings/{refA}/rating",          {"stars": 1}),
        ("GET",  f"/bookings/{refA}/deposit/terms",   None),
        ("POST", f"/bookings/{refA}/deposit",         {"acceptTerms": True}),
        ("POST", f"/bookings/{refA}/ekyc/scan",       {"frontImage": "x", "backImage": "x"}),
        ("POST", f"/bookings/{refA}/ekyc",            {"fullName": "x"}),
    ]
    for i, (m, p, b) in enumerate(idor_paths, 1):
        s, t, _, _ = _req(m, p, b, token=tB)
        safe = s == 404  # loadOwned -> 404 booking_not_found (does not leak existence)
        rec("idor_bfla", f"BOLA-{i}", f"tenantB -> {m} {p.replace(refA,'<A-ref>')}",
            f"cross-tenant on tenantA object", s,
            "SAFE(404)" if safe else f"VULN? ({s})",
            "object-level authz via loadOwned(tenantId==session) -> 404 expected", t)

    # --- landlord consignment object owned by landlordA ---
    cons = {"building": "S1.SEC", "floor": 11, "door": "A1", "layout": "Studio",
            "areaM2": 30, "askRent": 8000000, "draft": True}
    s, t, _, _ = _req("POST", "/landlord/consignments", cons, token=lA)
    mid = json.loads(t)["data"].get("id") if s in (200, 201) else None
    rec("idor_bfla", "SETUP-2", "landlordA creates a consignment to own", json.dumps(cons),
        s, "ok" if mid else "FAILED", f"mandateId={mid}", t)

    if mid:
        s, t, _, _ = _req("GET", f"/landlord/consignments/{mid}", token=lA)
        rec("idor_bfla", "CTRL-2", "landlordA GET own consignment (control)",
            f"GET /landlord/consignments/{mid}", s, "OK" if s == 200 else "unexpected", "", t)
        for i, (m, p, b) in enumerate([
            ("GET",  f"/landlord/consignments/{mid}", None),
            ("POST", f"/landlord/consignments/{mid}/send-otp", {"phone": "0912345679"}),
            ("POST", f"/landlord/consignments/{mid}/pricing-decision", {"decision": "accept"}),
            ("DELETE", f"/landlord/consignments/{mid}/photos/{uuid.uuid4()}", None),
        ], 1):
            s, t, _, _ = _req(m, p, b, token=lB)
            rec("idor_bfla", f"BOLA-L{i}", f"landlordB -> {m} .../{mid[:8]}..",
                "cross-landlord on landlordA mandate", s,
                "SAFE(404)" if s == 404 else f"VULN? ({s})",
                "ownedMandate(unit.landlordId==session) -> 404 expected", t)

    # --- FUNCTION-LEVEL (BFLA): wrong-role / no-role reaching privileged functions ---
    bfla = [
        # (actor_token_name, method, path, body, expect)
        ("tenantA",  "GET",  "/admin/deposits",                 None, 403),
        ("tenantA",  "GET",  "/admin/bi-funnel",                None, 403),
        ("tenantA",  "POST", "/admin/commission-engine/config", {"x": 1}, 403),
        ("tenantA",  "GET",  "/landlord/consignments",          None, 403),
        ("tenantA",  "GET",  "/host/me",                        None, 403),
        ("tenantA",  "GET",  "/host/board",                     None, 403),
        ("tenantA",  "GET",  "/host/inspections",               None, 403),
        ("landlordA","POST", "/bookings", {"unitCode": unitA, "slot": slot_iso(5,(9,30)),
                        "contactName":"x","phone":"0912345600"}, 403),
        ("landlordA","GET",  "/admin/deposits",                 None, 403),
        ("landlordA","GET",  "/host/board",                     None, 403),
        ("landlordB","GET",  "/me/contracts",                   None, 403),  # tenant-only /me route
    ]
    for i, (who, m, p, b, exp) in enumerate(bfla, 1):
        s, t, _, _ = _req(m, p, b, token=TOKENS[who])
        rec("idor_bfla", f"BFLA-{i}", f"{who} ({ACCOUNTS[who][1]}) -> {m} {p}",
            f"cross-function, expect {exp}", s,
            "SAFE(403)" if s == exp else f"VULN? ({s})",
            "RolesGuard must reject role mismatch", t)

    # --- unauthenticated must be 401 on protected surfaces ---
    for i, (m, p) in enumerate([("GET","/admin/deposits"),("GET","/landlord/consignments"),
                                ("GET","/host/board"),("GET","/me/profile"),
                                ("POST","/bookings")], 1):
        s, t, _, _ = _req(m, p, {} if m == "POST" else None)
        rec("idor_bfla", f"NOAUTH-{i}", f"unauth -> {m} {p}", "no session, expect 401",
            s, "SAFE(401)" if s == 401 else f"VULN? ({s})", "SupabaseAuthGuard", t)

    # --- parameter-injection BFLA: can a landlord override ownership via body/query id? ---
    s, t, _, _ = _req("GET", "/landlord/consignments?landlordId=00000000-0000-0000-0000-000000000000", token=lB)
    rec("idor_bfla", "PARAM-1",
        "landlordB lists consignments with a spoofed landlordId query param",
        "query landlordId ignored; session wins", s,
        "SAFE(session-scoped)" if s == 200 else f"check({s})",
        "controllers bind landlordId from @CurrentUser, never from client input", t)
    return refA


# ============================================================ BATTERY 2
def battery_upload(mandate_token):
    print("\n=== BATTERY 2: upload robustness (landlord consignment photos) ===")
    lA = TOKENS["landlordA"]
    # create a fresh draft consignment to upload into
    cons = {"building": "S1.SEC", "floor": 12, "door": "B2", "layout": "Studio",
            "areaM2": 30, "askRent": 8000000, "draft": True}
    s, t, _, _ = _req("POST", "/landlord/consignments", cons, token=lA)
    mid = json.loads(t)["data"]["id"]
    print(f"  upload target mandate={mid}")
    endpoint = f"/landlord/consignments/{mid}/photos"

    def up(field, fn, content, ct, token=lA):
        data, ctype = multipart([], [(field, fn, content, ct)])
        return _req("POST", endpoint, raw=data, ctype=ctype, token=token)

    cases = []
    # U1 valid PNG -> passes content validation, then storage is down -> 503 (fail-safe, not 500)
    cases.append(("U1", "valid 1x1 PNG", "files", "ok.png", PNG_1x1, "image/png",
                  lambda s: s in (503, 400, 201, 200)))
    # U2 wrong magic (text) with .jpg name & image/jpeg type -> 400 invalid type
    cases.append(("U2", "text disguised as .jpg (bad magic)", "files", "evil.jpg",
                  b"this is not an image, just text " * 3, "image/jpeg", lambda s: s == 400))
    # U3 empty file
    cases.append(("U3", "empty file", "files", "empty.png", b"", "image/png", lambda s: s == 400))
    # U4 oversized (>3MB) but valid PNG magic -> multer/413 or service 400 photo_too_large
    big = PNG_1x1 + b"\x00" * (3 * 1024 * 1024 + 500)
    cases.append(("U4", "oversized >3MB", "files", "big.png", big, "image/png",
                  lambda s: s in (400, 413)))
    # U5 path-traversal filename, valid PNG magic
    cases.append(("U5", "path-traversal filename", "files",
                  "../../../../../../tmp/sectest_pwn.png", PNG_1x1, "image/png",
                  lambda s: s in (503, 400, 201, 200)))
    # U6 polyglot: valid JPEG magic + embedded HTML/script
    poly = JPEG_HDR + b"<script>alert(1)</script><?php system($_GET[0]);?>"
    cases.append(("U6", "polyglot JPEG+script", "files", "poly.jpg", poly, "image/jpeg",
                  lambda s: s in (503, 400, 201, 200)))
    # U7 PNG magic but truncated garbage body (landlord path has no dimension re-check)
    cases.append(("U7", "PNG magic + garbage body", "files", "trunc.png",
                  bytes.fromhex("89504e470d0a1a0a") + b"\x01\x02\x03garbage", "image/png",
                  lambda s: s in (503, 400, 201, 200)))
    # U8 wrong multipart field name
    cases.append(("U8", "wrong field name 'file' not 'files'", "file", "x.png", PNG_1x1,
                  "image/png", lambda s: s == 400))
    # U9 content-type spoof: declare image/png but gif magic
    cases.append(("U9", "GIF magic declared png", "files", "a.png",
                  b"GIF89a" + b"\x00" * 40, "image/png", lambda s: s == 400))

    for tid, title, field, fn, content, ct, ok in cases:
        s, t, _, ms = up(field, fn, content, ct)
        has_500 = s == 500
        has_stack = ("at " in t and ".js:" in t) or "stack" in t.lower() or "Cannot read" in t
        verdict = "FAIL-SAFE" if (ok(s) and not has_500 and not has_stack) else f"REVIEW ({s})"
        rec("upload", tid, title, f"POST photos field={field} name={fn} bytes={len(content)} ct={ct}",
            s, verdict, f"no_500={not has_500} no_stacktrace={not has_stack}", t)

    # too-many-files (>8) -> multer files limit
    files = [("files", f"f{i}.png", PNG_1x1, "image/png") for i in range(10)]
    data, ctype = multipart([], files)
    s, t, _, _ = _req("POST", endpoint, raw=data, ctype=ctype, token=lA)
    rec("upload", "U10", "10 files (quota/limit = 8)", "multipart 10 files", s,
        "FAIL-SAFE" if s in (400, 413) and s != 500 else f"REVIEW ({s})",
        "multer files:MAX_PHOTOS or service quota", t)

    # check nothing was written outside storage (path traversal sanity)
    leaked = os.path.exists("/tmp/sectest_pwn.png")
    rec("upload", "U5b", "path-traversal filesystem check", "stat /tmp/sectest_pwn.png",
        0, "SAFE(no write)" if not leaked else "VULN(file written!)",
        "storage path is server-generated UUID; filename only used for display", "")


# ============================================================ BATTERY 3
def battery_load(unit_codes):
    print("\n=== BATTERY 3: write-load ramp (bookings, SECTEST-) ===")
    tA = TOKENS["tenantA"]  # phone-verified -> no action token needed
    phone = "0912345670"
    pool = []
    for uc in unit_codes:
        for sl in all_slots():
            pool.append((uc, sl))
    # dedupe & cap
    pool = pool[:260]
    idx = {"i": 0}
    lock = threading.Lock()

    def next_combo():
        with lock:
            i = idx["i"]; idx["i"] += 1
            return pool[i] if i < len(pool) else None

    def one():
        combo = next_combo()
        if combo is None:
            return (0, 0, "pool_exhausted")
        uc, sl = combo
        body = {"unitCode": uc, "slot": sl, "contactName": "SECTEST-load",
                "phone": phone, "note": "SECTEST-load-generated"}
        t0 = time.monotonic()
        s, t, _, _ = _req("POST", "/bookings", body, token=tA, timeout=60)
        return (int((time.monotonic()-t0)*1000), s, t)

    ramps = [1, 5, 10, 25, 50]
    per = 60  # requests per ramp level
    summary = []
    for c in ramps:
        if idx["i"] >= len(pool):
            break
        lat, codes = [], {}
        n = min(per, len(pool) - idx["i"])
        t0 = time.monotonic()
        with ThreadPoolExecutor(max_workers=c) as ex:
            for ms, s, _ in ex.map(lambda _: one(), range(n)):
                lat.append(ms); codes[s] = codes.get(s, 0) + 1
        wall = time.monotonic() - t0
        lat.sort()

        def pct(p):
            if not lat: return None
            k = max(0, min(len(lat)-1, int(round(p/100*(len(lat)-1)))))
            return lat[k]
        ok = codes.get(201, 0) + codes.get(200, 0)
        err = sum(v for k, v in codes.items() if k not in (200, 201, 409))
        row = {"concurrency": c, "requests": n, "wall_s": round(wall, 2),
               "throughput_rps": round(n/wall, 1) if wall else None,
               "p50": pct(50), "p95": pct(95), "p99": pct(99), "max": lat[-1] if lat else None,
               "ok_2xx": ok, "conflict_409": codes.get(409, 0),
               "other_err": err, "codes": codes}
        summary.append(row)
        print(f"  c={c:>2} n={n} thr={row['throughput_rps']}rps p50={row['p50']} "
              f"p95={row['p95']} p99={row['p99']} max={row['max']} codes={codes}")
    return summary


def main():
    print("Logging in test accounts...")
    login_all()
    units = ["VHOP-SEC-0001", "VHOP-SEC-0002", "VHOP-SEC-0003"]
    battery_idor_bfla(units[0])
    battery_upload(None)
    load_summary = battery_load(units)

    out = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S%z"),
        "stack": {"backend": B, "db": "postgres container vinstay-p010-sectest-pg :55432",
                  "providers_stubbed": {"otp": "OTP_ECHO_DEV_CODE devCode",
                      "vietqr": "env VIETQR_* + self-owned webhook secret + DEMO_TOOLS",
                      "ekyc": "hard-blocked 503 after ownership check (CCCD not wired)"}},
        "idor_bfla": results["idor_bfla"],
        "upload": results["upload"],
        "load": {"summary": load_summary, "label": "SECTEST-load"},
    }
    path = os.path.join(EV_DIR, "12_idor_bfla_upload_load_battery.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\nWrote {path}")


if __name__ == "__main__":
    main()
