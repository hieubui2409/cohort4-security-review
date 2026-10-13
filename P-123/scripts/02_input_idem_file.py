"""Battery 1 (input caps + /analyze gate), 3 (idempotency), 5 (file robustness).
All writes labelled SECTEST-. Created case ids printed for cleanup."""
import sys, os, time, uuid, json
sys.path.insert(0, os.path.dirname(__file__))
from importlib import import_module
lib = import_module("02_lib")
import httpx

BASE = lib.BASE
created_cases = []
results = {}

ct = lib.login("customer")
ck = lib.login("cskh")
CH = lib.hdr(ct)
CSKH = lib.hdr(ck)

# A completed trip owned by customer01 (from recon)
TRIP = "e0017bde-c3ea-5f18-9f87-5981ba17cc2c"  # GC-TRIP-00003 (rating None)

def post_case(body, key=None, h=CH):
    headers = dict(h)
    if key:
        headers["Idempotency-Key"] = key
    r = httpx.post(f"{BASE}/cases", json=body, headers=headers, timeout=60)
    try:
        j = r.json()
    except Exception:
        j = {"_raw": r.text[:300]}
    return r.status_code, j

def base_case(complaint, title=None, category="LOST_ITEM", evidence=None):
    return {
        "title": title or (lib.MARK + "case " + uuid.uuid4().hex[:8]),
        "complaint": complaint,
        "category": category,
        "trip_id": TRIP,
        "channel": "app",
        "customer_evidence": evidence or [],
    }

# ---------- Battery 1: input length caps ----------
b1 = {}
# complaint over 20000 chars -> expect 422 VALIDATION_ERROR, NO case created
big = lib.MARK + ("A" * 20001)
sc, j = post_case(base_case(big))
b1["complaint_20001_chars"] = {"status": sc, "code": (j.get("error") or {}).get("code"), "fields": (j.get("error") or {}).get("details")}
# title over 200
body = base_case(lib.MARK + "ok complaint here", title=lib.MARK + "T"*201)
sc, j = post_case(body)
b1["title_201_chars"] = {"status": sc, "code": (j.get("error") or {}).get("code")}
# complaint below min (10)
sc, j = post_case(base_case("short"))
b1["complaint_too_short"] = {"status": sc, "code": (j.get("error") or {}).get("code")}
# CSKH note over 10000
# find any case id CSKH can see
cases_all = httpx.get(f"{BASE}/cases", headers=CSKH, timeout=60).json()
any_case = cases_all[0]["id"] if isinstance(cases_all, list) and cases_all else None
if any_case:
    r = httpx.post(f"{BASE}/cases/{any_case}/notes", json={"content": lib.MARK + "N"*10001}, headers=CSKH, timeout=60)
    b1["note_10001_chars"] = {"status": r.status_code, "code": (r.json().get("error") or {}).get("code")}
results["battery1_input_caps"] = b1

# ---------- Battery 1: /analyze gate (cost endpoint) ----------
b1g = {}
# customer tries analyze -> expect 403 (role)
if any_case:
    r = httpx.post(f"{BASE}/cases/{any_case}/analyze", headers=CH, timeout=60)
    b1g["customer_analyze"] = {"status": r.status_code, "code": (r.json().get("error") or {}).get("code")}
    # cskh analyze on a case NOT in analyze-eligible state -> expect INVALID_STATE_TRANSITION (no Gemini spent)
    r = httpx.post(f"{BASE}/cases/{any_case}/analyze", headers=CSKH, timeout=90)
    b1g["cskh_analyze_badstate_case0"] = {"status": r.status_code, "code": (r.json().get("error") or {}).get("code"), "msg": (r.json().get("error") or {}).get("message")}
results["battery1_analyze_gate"] = b1g

# ---------- Battery 3: idempotency ----------
b3 = {}
key = "SECTEST-idem-" + uuid.uuid4().hex[:10]
body = base_case(lib.MARK + "idempotency probe body")
sc1, j1 = post_case(body, key=key)
id1 = j1.get("id")
if id1: created_cases.append(id1)
sc2, j2 = post_case(body, key=key)            # same key + same body -> dedup, same id
id2 = j2.get("id")
# same key + DIFFERENT body -> IDEMPOTENCY_CONFLICT
sc3, j3 = post_case(base_case(lib.MARK + "idempotency DIFFERENT body"), key=key)
b3 = {
    "first": {"status": sc1, "id": id1, "code": (j1.get("error") or {}).get("code")},
    "replay_same_body": {"status": sc2, "id": id2, "same_id_as_first": id2 == id1},
    "replay_diff_body": {"status": sc3, "code": (j3.get("error") or {}).get("code"), "msg": (j3.get("error") or {}).get("message")},
}
results["battery3_idempotency"] = b3

# ---------- Battery 5: file robustness (customer base64 image path) ----------
b5 = {}
def ev(name, b64str, mime):
    return [{"original_name": name, "mime_type": mime, "image_base64": b64str, "description": lib.MARK}]

# (a) decoded > 10MB but under schema 14M char cap -> INVALID_FILE_SIZE 422, rolled back
big_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * (10 * 1024 * 1024 + 50)
sc, j = post_case(base_case(lib.MARK + "oversize file", evidence=ev("big.png", lib.b64(big_bytes), "image/png")))
if j.get("id"): created_cases.append(j["id"])
b5["decoded_over_10MB"] = {"status": sc, "code": (j.get("error") or {}).get("code")}

# (b) base64 over schema cap 14,000,000 chars -> 422 VALIDATION_ERROR (pydantic), no server strain
huge_b64 = "A" * 14_000_050
sc, j = post_case(base_case(lib.MARK + "schema cap", evidence=ev("huge.png", huge_b64, "image/png")))
if j.get("id"): created_cases.append(j["id"])
b5["b64_over_schema_cap"] = {"status": sc, "code": (j.get("error") or {}).get("code")}

# (c) MIME mismatch: junk bytes labelled image/png -> INVALID_FILE 422
sc, j = post_case(base_case(lib.MARK + "mime junk", evidence=ev("x.png", lib.b64(b"not an image at all"), "image/png")))
if j.get("id"): created_cases.append(j["id"])
b5["junk_bytes_as_png"] = {"status": sc, "code": (j.get("error") or {}).get("code")}

# (d) real PNG declared as image/jpeg -> format mismatch INVALID_FILE 422
sc, j = post_case(base_case(lib.MARK + "fmt mismatch", evidence=ev("x.jpg", lib.b64(lib.tiny_png()), "image/jpeg")))
if j.get("id"): created_cases.append(j["id"])
b5["png_declared_jpeg"] = {"status": sc, "code": (j.get("error") or {}).get("code")}

# (e) pixel bomb: 9000x9000 solid PNG (81M px > 40M) -> IMAGE_TOO_LARGE 422 (small file)
bomb = lib.tiny_png(9000, 9000)
sc, j = post_case(base_case(lib.MARK + "pixel bomb", evidence=ev("bomb.png", lib.b64(bomb), "image/png")))
if j.get("id"): created_cases.append(j["id"])
b5["pixel_bomb_9000x9000"] = {"status": sc, "code": (j.get("error") or {}).get("code"), "png_bytes": len(bomb)}

# (f) filename traversal: Path().name should strip; this is a VALID small png -> case created, name stored basename
sc, j = post_case(base_case(lib.MARK + "traversal name", evidence=ev("../../../../etc/passwd.png", lib.b64(lib.tiny_png()), "image/png")))
if j.get("id"):
    created_cases.append(j["id"])
    b5["filename_traversal"] = {"status": sc, "created": True, "note": "stored basename only (see customer-evidence)"}
else:
    b5["filename_traversal"] = {"status": sc, "code": (j.get("error") or {}).get("code")}
results["battery5_file_robustness"] = b5

results["_created_cases"] = created_cases
print(json.dumps(results, ensure_ascii=False, indent=2, default=str))
lib.save_evidence("02_input_idem_file.json", results)
