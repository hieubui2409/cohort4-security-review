#!/usr/bin/env python3
"""P-010 VinStay AI — DYNAMIC battery 09: host<->host IDOR + deposit happy-path & IDOR + eKYC/contract (A18).

Closes the 3 items the earlier report left "not dynamically run" (host-vs-host object IDOR, deposit happy-path +
deposit-record IDOR, eKYC/contract downstream). Barriers that needed multiple actors / hard-stubbed providers are
crossed by SEEDING the isolated Postgres directly (scripts/09_seed_host_deposit_ekyc.js), then every assertion is
exercised over real HTTP against the real NestJS backend.

Stub technique (same spirit as EV-08): OTP echo devCode; VietQR = env creds + self-owned webhook secret + DEMO_TOOLS;
eKYC provider still throws 503 (hard stub) BUT the contract downstream is reached by seeding a VERIFIED
IdentityVerification + Contract and enabling the LOCAL lease-pdf store (LEASE_PDF_LOCAL_DIR) so the sealed PDF renders
locally with no external provider.

stdlib only; run with `python3 -I` from OUTSIDE the app repo. Reads seed ids from SEED_OUT json file (argv[1]).
Writes JSON evidence to evidences/13_host_idor_deposit_ekyc_battery.json.
"""
import json, sys, time, hashlib, urllib.request, urllib.error

B = "http://127.0.0.1:4000/api/v1"
EV = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-010/evidences/13_host_idor_deposit_ekyc_battery.json"
PASSWORD = "<REDACTED_PASSWORD>"
WEBHOOK_SECRET = "<REDACTED_SECRET>"

SEED = json.load(open(sys.argv[1] if len(sys.argv) > 1 else sys.exit("usage: battery.py <seed.json>")))

ACCOUNTS = {
    "tenantA":   ("sectest.tenanta@example.com",   "tenant"),
    "tenantB":   ("sectest.tenantb@example.com",   "tenant"),
    "landlordA": ("sectest.landlorda@example.com", "landlord"),
    "landlordB": ("sectest.landlordb@example.com", "landlord"),
    "hostA":     ("sectest.hosta@example.com",     "host"),
    "hostB":     ("sectest.hostb@example.com",     "host"),
    "opsAdmin":  ("sectest.opsadmin@example.com",  "admin"),
}
TOK = {}
results = {"host_idor": [], "deposit": [], "ekyc_contract": []}


def _req(method, path, body=None, token=None, headers=None, timeout=60):
    h = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    if token:
        h["Cookie"] = f"vs_access={token}"
    req = urllib.request.Request(B + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return 0, f"ERR {type(e).__name__}: {e}", {}


def login_once(email, portal):
    req = urllib.request.Request(B + "/auth/login", method="POST",
        data=json.dumps({"email": email, "password": PASSWORD, "portal": portal}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            for c in (r.headers.get_all("Set-Cookie") or []):
                if c.startswith("vs_access="):
                    return r.status, c.split("=", 1)[1].split(";", 1)[0]
        return r.status, None
    except urllib.error.HTTPError as e:
        return e.code, None


def login_all():
    # /auth/login is throttled per-IP; space out + back off on 429 so every principal gets a session.
    for name, (email, portal) in ACCOUNTS.items():
        tok, code = None, None
        for attempt in range(8):
            code, tok = login_once(email, portal)
            if tok:
                break
            time.sleep(2.0 if code == 429 else 1.0)
        TOK[name] = tok
        print(f"  login {name}: {'ok' if tok else 'MISSING(%s)' % code}")
        time.sleep(1.2)  # stay under the login rate limit


def code_of(txt):
    try:
        return json.loads(txt).get("code")
    except Exception:
        return None


def rec(group, tid, title, inp, status, verdict, note, output=""):
    r = {"id": tid, "title": title, "input": inp, "http": status, "code": code_of(output),
         "verdict": verdict, "note": note, "output_excerpt": (output or "")[:500],
         "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    results[group].append(r)
    print(f"  [{tid}] http={status} {verdict} :: {title}")
    return r


# ============================================================ BATTERY A: host<->host IDOR
def battery_host_idor():
    print("\n=== BATTERY A: host<->host object IDOR (SALE tickets+viewings, INSPECTOR cases) ===")
    tA, tB = TOK["hostA"], TOK["hostB"]
    tkA, tkB = SEED["ticketHA"], SEED["ticketHB"]
    rA, rB = SEED["refs"]["vHA"], SEED["refs"]["vHB"]
    mandate = SEED["mandateId"]

    # --- owner CONTROLS: host A drives its own ticket/viewing lifecycle live ---
    s, t, _ = _req("POST", f"/host/tickets/{tkA}/accept", None, token=tA)
    rec("host_idor", "CTRL-A1", "hostA accepts OWN ticket (OFFERED->CONFIRMED)", f"POST /host/tickets/<A>/accept",
        s, "OK" if s == 200 else f"unexpected({s})", "owner must succeed", t)
    s, t, _ = _req("POST", f"/host/tickets/{tkB}/accept", None, token=tB)
    rec("host_idor", "CTRL-B1", "hostB accepts OWN ticket", "POST /host/tickets/<B>/accept",
        s, "OK" if s == 200 else f"unexpected({s})", "owner must succeed", t)
    s, t, _ = _req("GET", f"/host/viewings/{rA}", None, token=tA)
    rec("host_idor", "CTRL-A2", "hostA GET OWN viewing", f"GET /host/viewings/{rA}",
        s, "OK" if s == 200 else f"unexpected({s})", "owner read", t)
    s, t, _ = _req("POST", f"/host/viewings/{rA}/receive", None, token=tA)
    rec("host_idor", "CTRL-A3", "hostA receive OWN viewing (CONFIRMED->RECEIVING)", f"POST /host/viewings/{rA}/receive",
        s, "OK" if s == 200 else f"unexpected({s})", "owner lifecycle transition", t)

    # --- IDOR: host B acts on host A's TICKET ---
    for i, (m, p, b) in enumerate([
        ("POST", f"/host/tickets/{tkA}/accept", None),
        ("POST", f"/host/tickets/{tkA}/reject", {"reason": "SECTEST idor reject"}),
        ("POST", f"/host/tickets/{tkA}/claim", None),
    ], 1):
        s, t, _ = _req(m, p, b, token=tB)
        safe = s in (403, 404, 409)
        rec("host_idor", f"TKT-{i}", f"hostB -> {m} {p.replace(tkA,'<A-ticket>')}", "cross-host on hostA ticket",
            s, "SAFE" if safe else f"VULN?({s})", "ticket.hostId!=B -> ticket_not_found/not_open expected", t)

    # --- IDOR: host B acts on host A's VIEWING (every lifecycle verb) ---
    vpaths = [
        ("GET",  f"/host/viewings/{rA}", None),
        ("POST", f"/host/viewings/{rA}/remind", None),
        ("POST", f"/host/viewings/{rA}/receive", None),
        ("POST", f"/host/viewings/{rA}/open-door", None),
        ("POST", f"/host/viewings/{rA}/door-code", None),
        ("POST", f"/host/viewings/{rA}/no-show", None),
        ("POST", f"/host/viewings/{rA}/start-deposit", None),
        ("POST", f"/host/viewings/{rA}/not-interested", {"reason": "SECTEST reason text"}),
        ("POST", f"/host/viewings/{rA}/emergency", {"kind": "smart_lock", "note": "SECTEST"}),
    ]
    for i, (m, p, b) in enumerate(vpaths, 1):
        s, t, _ = _req(m, p, b, token=tB)
        safe = s in (403, 404)
        rec("host_idor", f"VW-{i}", f"hostB -> {m} {p.replace(rA,'<A-ref>')}", "cross-host on hostA viewing",
            s, "SAFE" if safe else f"VULN?({s})", "loadOwned requires B's accepted ticket -> viewing_not_found", t)

    # reverse direction spot-check: host A on host B's viewing
    s, t, _ = _req("GET", f"/host/viewings/{rB}", None, token=tA)
    rec("host_idor", "REV-1", "hostA -> GET hostB viewing", f"GET /host/viewings/{rB}",
        s, "SAFE" if s in (403, 404) else f"VULN?({s})", "symmetric ownership", t)

    # --- IDOR: host B on host A's INSPECTION case (assertCaseOwner) ---
    s, t, _ = _req("GET", f"/host/inspections/{mandate}", None, token=tA)
    rec("host_idor", "INS-CTRL", "hostA GET OWN inspection case (control)", f"GET /host/inspections/<mandateA>",
        s, "OK" if s == 200 else f"check({s})", "meta.hostId==A, stage inspecting", t)
    valid_submit = {"declared": [], "inventory": [], "functions": {"ac": True, "kitchen": True, "waterHeater": True, "drainage": True},
                    "netAreaM2": 30, "furnishing": "basic", "listingPhotoIds": [], "recommendation": "reject", "note": "SECTEST reject"}
    for i, (m, p, b) in enumerate([
        ("GET",  f"/host/inspections/{mandate}", None),
        ("POST", f"/host/inspections/{mandate}/door-code", None),
        ("POST", f"/host/inspections/{mandate}/submit", valid_submit),
        ("POST", f"/host/inspections/{mandate}/claim", None),
    ], 1):
        s, t, _ = _req(m, p, b, token=tB)
        safe = s in (403, 404, 409)  # 404 inspection_not_found (assertCaseOwner) / 409 claim refused (not awaiting_host) = both rejections
        rec("host_idor", f"INS-{i}", f"hostB -> {m} .../inspections/<mandateA>..", "cross-host on hostA case",
            s, "SAFE" if safe else f"VULN?({s})", "assertCaseOwner meta.hostId!=B -> inspection_not_found; claim open-pool-only", t)

    # --- parameter-injection: does a client-supplied hostId change scope? board must be session-scoped ---
    s, t, _ = _req("GET", "/host/board", None, token=tB)
    leaks_A = rA in t
    rec("host_idor", "PARAM-1", "hostB GET /host/board does not expose hostA's viewing", "session-scoped board",
        s, "SAFE" if (s == 200 and not leaks_A) else f"REVIEW({s},leakA={leaks_A})",
        "board resolves host from session, no client hostId", t)


# ============================================================ BATTERY B: deposit happy-path + IDOR + webhook auth
def battery_deposit():
    print("\n=== BATTERY B: deposit happy-path + record IDOR + webhook auth ===")
    tA, tB = TOK["tenantA"], TOK["tenantB"]
    lB = TOK["landlordB"]
    ref = SEED["refs"]["vDep"]  # viewing seeded in CLOSING, owned by tenantA

    # happy-path step 1: terms + create
    s, t, _ = _req("GET", f"/bookings/{ref}/deposit/terms", None, token=tA)
    rec("deposit", "HP-1", "tenantA GET deposit terms (owner)", f"GET /bookings/{ref}/deposit/terms",
        s, "OK" if s == 200 else f"unexpected({s})", "", t)
    s, t, _ = _req("POST", f"/bookings/{ref}/deposit", {"acceptTerms": True, "termsVersion": "HOLD-2026.10-v1"}, token=tA)
    created = s in (200, 201)
    dep_code = None
    try:
        dep_code = json.loads(t)["data"].get("deposit", {}).get("code") or f"DEP-{ref}"
    except Exception:
        dep_code = f"DEP-{ref}"
    rec("deposit", "HP-2", "tenantA createDeposit (CLOSING -> PENDING_PAYMENT)", f"POST /bookings/{ref}/deposit",
        s, "OK" if created else f"FAILED({s})", f"depositCode~={dep_code}", t)

    # webhook auth: missing signature, wrong signature, then correct
    body = {"depositCode": f"DEP-{ref}", "amount": 2000000, "bankRefNumber": "SECTEST-BANK-WRONG-1"}
    s, t, _ = _req("POST", "/vietqr/webhook", body, headers={})
    rec("deposit", "WH-1", "webhook with NO x-vietqr-secret header", "missing signature", s,
        "SAFE(reject)" if s in (401, 403) else f"VULN?({s})", "constant-time secret compare; empty != secret", t)
    s, t, _ = _req("POST", "/vietqr/webhook", body, headers={"x-vietqr-secret": "totally-wrong-secret"})
    rec("deposit", "WH-2", "webhook with WRONG x-vietqr-secret", "bad signature", s,
        "SAFE(401)" if s == 401 else f"VULN?({s})", "webhook_secret_invalid expected", t)
    # correct secret -> markPaid
    body_ok = {"depositCode": f"DEP-{ref}", "amount": 2000000, "bankRefNumber": "SECTEST-BANK-OK-1"}
    s, t, _ = _req("POST", "/vietqr/webhook", body_ok, headers={"x-vietqr-secret": WEBHOOK_SECRET})
    paid = False
    try:
        paid = json.loads(t).get("data", {}).get("outcome") in ("paid", "duplicate")
    except Exception:
        pass
    rec("deposit", "WH-3", "webhook with CORRECT secret -> markPaid", "valid signature + matched deposit", s,
        "OK(paid)" if (s in (200, 201) and paid) else f"REVIEW({s})", "deposit reaches PAID_HOLDING (201 = Nest POST default)", t)

    # confirm PAID via owner read
    s, t, _ = _req("GET", f"/bookings/{ref}", None, token=tA)
    is_paid = ('"holding"' in t.lower()) or ("paid" in t.lower())
    rec("deposit", "HP-3", "tenantA reads booking; deposit now paid/holding", f"GET /bookings/{ref}",
        s, "OK" if s == 200 and is_paid else f"REVIEW({s})", "deposit status reflects PAID_HOLDING", t)

    # --- deposit record IDOR: tenantB / landlordB touch tenantA's deposit via the booking ref ---
    for i, (who, tok, m, p, b) in enumerate([
        ("tenantB", tB, "GET",  f"/bookings/{ref}", None),
        ("tenantB", tB, "GET",  f"/bookings/{ref}/deposit/terms", None),
        ("tenantB", tB, "POST", f"/bookings/{ref}/deposit", {"acceptTerms": True, "termsVersion": "HOLD-2026.10-v1"}),
        ("tenantB", tB, "POST", f"/bookings/{ref}/deposit/demo-pay", None),
        ("landlordB", lB, "GET", f"/bookings/{ref}", None),
    ], 1):
        s, t, _ = _req(m, p, b, token=tok)
        safe = s in (403, 404)
        rec("deposit", f"IDOR-{i}", f"{who} -> {m} {p.replace(ref,'<A-ref>')}", "cross-actor on tenantA deposit",
            s, "SAFE" if safe else f"VULN?({s})", "loadOwned viewing.tenantId!=actor / role guard", t)

    # replayed/forged webhook pointed at the deposit by content (no auth header) must still be rejected
    s, t, _ = _req("POST", "/vietqr/webhook", {"transferContent": "COC SECTEST-U-DEP " + ref,
                   "amount": 2000000, "bankRefNumber": "SECTEST-BANK-FORGE-1"}, headers={})
    rec("deposit", "WH-4", "forged webhook (content match) with NO secret", "unauth payment injection", s,
        "SAFE(reject)" if s in (401, 403) else f"VULN?({s})", "no secret -> no markPaid regardless of content", t)


# ============================================================ BATTERY C: eKYC / contract downstream (A18)
def battery_ekyc_contract():
    print("\n=== BATTERY C: eKYC provider 503 + contract downstream reached by seed + IDOR ===")
    tA, tB = TOK["tenantA"], TOK["tenantB"]
    lA = TOK["landlordA"]
    cid = SEED["contractId"]
    refCon = SEED["refs"]["vCon"]
    refDep = SEED["refs"]["vDep"]

    # (a) confirm eKYC provider is still a hard 503 for the OWNER, and 404 cross-tenant (ownership before 503)
    s, t, _ = _req("POST", f"/bookings/{refDep}/ekyc/scan", {"consent": True, "consentVersion": "KYC-2026.10-v1"}, token=tA)
    rec("ekyc_contract", "EK-1", "tenantA eKYC scan on OWN booking", f"POST /bookings/{refDep}/ekyc/scan",
        s, "503(hard-stub)" if s == 503 else f"NOTE({s})", "provider unconditionally 503 ekyc_provider_unavailable", t)
    s, t, _ = _req("POST", f"/bookings/{refDep}/ekyc/scan", {"consent": True, "consentVersion": "KYC-2026.10-v1"}, token=tB)
    rec("ekyc_contract", "EK-2", "tenantB eKYC scan on tenantA booking (IDOR)", f"POST /bookings/{refDep}/ekyc/scan",
        s, "SAFE(404)" if s == 404 else f"VULN?({s})", "loadOwned runs BEFORE 503 -> cross-tenant 404", t)
    s, t, _ = _req("POST", f"/bookings/{refDep}/ekyc", {"scanId": "SECTEST-scan", "consentVersion": "KYC-2026.10-v1",
                   "fields": {"fullName": "SECTEST", "idNumber": "001099012345", "dob": "01/01/1995",
                              "issuedDate": "01/01/2021", "address": "SECTEST addr"},
                   "confirmedLowConfidence": True,
                   "lease": {"startDate": "2026-11-01", "months": 12, "paymentCycle": 1}}, token=tB)
    rec("ekyc_contract", "EK-3", "tenantB eKYC submit (A18) on tenantA booking (IDOR)", f"POST /bookings/{refDep}/ekyc",
        s, "SAFE(404)" if s == 404 else f"VULN?({s})", "ownership gate before contract-create/503", t)

    # (b) DOWNSTREAM reached via seed: owner lists + downloads the sealed lease PDF (bypasses provider 503)
    s, t, _ = _req("GET", "/me/contracts", None, token=tA)
    has = SEED["contractNumber"] in t
    rec("ekyc_contract", "CT-1", "tenantA lists own contracts (downstream reachable)", "GET /me/contracts",
        s, "OK" if s == 200 and has else f"REVIEW({s})", "seeded VERIFIED identity + Contract", t)
    s, t, hdr = _req("GET", f"/me/contracts/{cid}/pdf", None, token=tA)
    is_pdf = hdr.get("Content-Type", "").startswith("application/pdf") or t.startswith("%PDF")
    rec("ekyc_contract", "CT-2", "tenantA downloads OWN sealed lease PDF (downstream executed)",
        f"GET /me/contracts/{cid}/pdf", s, "OK(pdf sealed)" if s == 200 and is_pdf else f"REVIEW({s})",
        "renders+seals locally; eKYC provider 503 NOT on this path", (t[:60] if is_pdf else t))

    # (c) CONTRACT IDOR: tenantB reads list (must not see A) + downloads A's contract pdf
    s, t, _ = _req("GET", "/me/contracts", None, token=tB)
    leaks = SEED["contractNumber"] in t
    rec("ekyc_contract", "CT-IDOR-1", "tenantB lists contracts (must not contain tenantA's)", "GET /me/contracts",
        s, "SAFE" if (s == 200 and not leaks) else f"VULN?({s},leak={leaks})", "where tenantId==session", t)
    s, t, _ = _req("GET", f"/me/contracts/{cid}/pdf", None, token=tB)
    rec("ekyc_contract", "CT-IDOR-2", "tenantB downloads tenantA's contract PDF (IDOR)", f"GET /me/contracts/{cid}/pdf",
        s, "SAFE(404)" if s == 404 else f"VULN?({s})", "lease-pdf contract.tenantId!=session -> 404", t)
    # landlord cannot use tenant /me route at all (BFLA)
    s, t, _ = _req("GET", f"/me/contracts/{cid}/pdf", None, token=lA)
    rec("ekyc_contract", "CT-IDOR-3", "landlordA hits tenant-only /me/contracts/:id/pdf (BFLA)",
        f"GET /me/contracts/{cid}/pdf", s, "SAFE(403)" if s == 403 else f"VULN?({s})", "RolesGuard tenant-only", t)

    # (d) handover read of this contract: cross-tenant must not read (tenant route allows tenant/landlord/admin)
    s, t, _ = _req("GET", f"/handovers/contracts/{cid}", None, token=tB)
    rec("ekyc_contract", "CT-IDOR-4", "tenantB reads handover of tenantA's contract", f"GET /handovers/contracts/{cid}",
        s, "SAFE" if s in (403, 404) else f"VULN?({s})", "handover must scope to contract parties", t)


def main():
    print("Logging in principals...")
    login_all()
    battery_host_idor()
    battery_deposit()
    battery_ekyc_contract()

    def vulns(group):
        return [r for r in results[group] if r["verdict"].startswith("VULN")]
    out = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S%z"),
        "stack": {"backend": B, "db": "postgres container vinstay-p010-sectest2-pg :55432",
                  "seed_script": "scripts/09_seed_host_deposit_ekyc.js",
                  "providers": {"otp": "echo devCode", "vietqr": "env + self-owned webhook secret + DEMO_TOOLS",
                                "ekyc": "provider 503 hard-stub; downstream reached via seeded VERIFIED identity + Contract + LEASE_PDF_LOCAL_DIR"}},
        "seed_ids": SEED,
        "host_idor": results["host_idor"],
        "deposit": results["deposit"],
        "ekyc_contract": results["ekyc_contract"],
        "vuln_summary": {g: len(vulns(g)) for g in results},
    }
    with open(EV, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\nWrote {EV}")
    print("VULN counts:", out["vuln_summary"])


if __name__ == "__main__":
    main()
