"""Battery 4: login throttle (20/5min per ip+account) + X-Forwarded-For bypass probe.
Throwaway usernames only; no real account is locked. ~50 light requests total."""
import sys, os, json, uuid, time, httpx
sys.path.insert(0, os.path.dirname(__file__))
from importlib import import_module
lib = import_module("02_lib"); BASE = lib.BASE
out = {}

def attempt(username, extra_headers=None):
    h = {"Content-Type": "application/json"}
    if extra_headers: h.update(extra_headers)
    r = httpx.post(f"{BASE}/auth/login",
                   json={"username": username, "password": "SECTEST-wrong-pw", "role": "customer"},
                   headers=h, timeout=30)
    try: code = (r.json().get("error") or {}).get("code")
    except Exception: code = None
    return r.status_code, code

# Test A: fixed headers -> expect 429 RATE_LIMITED after ~20
uA = "SECTEST-rl-" + uuid.uuid4().hex[:8]
seqA = []
for i in range(23):
    sc, code = attempt(uA)
    seqA.append((i+1, sc, code))
    if sc == 429: break
    time.sleep(0.15)
out["A_fixed"] = {"username": uA, "sequence": seqA, "hit_429": any(sc==429 for _,sc,_ in seqA),
                  "first_429_at": next((i for i,sc,_ in seqA if sc==429), None)}

# Test B: rotating X-Forwarded-For + X-Real-IP -> does spoofing bypass the per-IP bucket?
uB = "SECTEST-rl-" + uuid.uuid4().hex[:8]
seqB = []
for i in range(25):
    ip = f"10.{i}.{(i*7)%256}.{(i*13)%256}"
    sc, code = attempt(uB, {"X-Forwarded-For": ip, "X-Real-IP": ip, "Forwarded": f"for={ip}"})
    seqB.append((i+1, sc, code, ip))
    if sc == 429: break
    time.sleep(0.15)
out["B_rotating_xff"] = {"username": uB, "count": len(seqB), "hit_429": any(sc==429 for _,sc,_,_ in seqB),
                         "first_429_at": next((i for i,sc,_,_ in seqB if sc==429), None),
                         "tail": seqB[-4:]}
out["interpretation"] = ("XFF ignored (limit enforced on real peer IP) => bypass NOT possible"
                         if out["B_rotating_xff"]["hit_429"] else
                         "XFF appears trusted => rotating XFF bypassed per-IP throttle")
print(json.dumps(out, ensure_ascii=False, indent=2))
lib.save_evidence("02_rate_limit.json", out)
