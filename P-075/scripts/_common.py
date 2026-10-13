"""Shared helpers for P-075 extended battery (dynamic API tests).

Safety rails honoured by callers:
  - concurrency burst <= 30
  - stop a load loop on >= 3 consecutive 5xx
  - never delete/modify other users' data
  - every created record is labelled with the SECTEST- prefix and its id recorded
"""
import json
import os
import time

import requests

BASE = "https://<REDACTED_DEPLOY>/api/v2"
ROOT = "/home/hieubt15/Documents/demo-review-cohort4"
CREDS = json.load(open(f"{ROOT}/handoff/T-075/demo-credentials.json"))
EVID = f"{ROOT}/reviews/P-075/evidences"
SECTEST = "SECTEST-"  # label prefix for everything we create


def login(email):
    r = requests.post(f"{BASE}/auth/login", json={"email": email, "password": CREDS[email]}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def H(tok, **extra):
    h = {"Authorization": f"Bearer {tok}"}
    h.update(extra)
    return h


def save(name, obj):
    os.makedirs(EVID, exist_ok=True)
    path = f"{EVID}/{name}"
    with open(path, "w") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
    print("saved ->", path)
    return path


def body_snip(r, n=300):
    try:
        return r.text[:n]
    except Exception:
        return "<no body>"
