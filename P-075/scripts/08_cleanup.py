#!/usr/bin/env python3
"""Cleanup — close every SECTEST- report created by the battery (reversible undo).

Reports have no API delete; the owner may CLOSE them (POST /reports/{id}/close), which
removes them from the active flow. We fetch the current revision/status, then close with a
labelled reason. Hard DB deletion (if the mentor wants the rows gone) is documented in
evidences/CLEANUP_P075.md.
"""
import sys, json
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from _common import BASE, H, login, save
import requests

tok = login("<REDACTED_EMAIL>")
IDS = [
    "a35a3b41-50d4-4680-bbf7-3eb7b4815600",  # 03_caching idempotency demo (trip T163)
    "07554453-a172-45b7-ad3c-b794a2140a43",  # 07 race same-key (trip WF-20261009-1-2)
    "8a2f48ec-36fa-4aa8-92e0-054233106096",  # 07 race diff-keys (trip WF-20261009-1-3)
]
out = {"base": BASE, "closed": []}
for rid in IDS:
    g = requests.get(f"{BASE}/reports/{rid}", headers=H(tok), timeout=30)
    if g.status_code != 200:
        out["closed"].append({"id": rid, "get_status": g.status_code, "note": g.text[:120]})
        print(rid, "GET", g.status_code)
        continue
    j = g.json()
    rev, st = j.get("revision"), j.get("status")
    c = requests.post(f"{BASE}/reports/{rid}/close", headers=H(tok),
                      json={"reason": "SECTEST cleanup - close synthetic security-test report", "expected_revision": rev}, timeout=30)
    cj = {}
    try:
        cj = c.json()
    except Exception:
        pass
    out["closed"].append({"id": rid, "pre_status": st, "pre_revision": rev,
                          "close_status": c.status_code, "post_status": cj.get("status"),
                          "note": None if c.status_code == 200 else c.text[:160]})
    print(f"{rid}: was {st}/rev{rev} -> close {c.status_code} -> {cj.get('status')}")

save("08_cleanup_result.json", out)
