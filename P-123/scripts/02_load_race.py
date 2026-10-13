"""Battery 7: light load ramp (GET /cases read; POST /cases write) + race tests.
Safety: abort a level if p99>5s or error-rate>10%. Writes labelled SECTEST-."""
import sys, os, json, uuid, time, statistics, httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(__file__))
from importlib import import_module
lib = import_module("02_lib"); BASE = lib.BASE

ct = lib.login("customer"); CH = lib.hdr(ct)
ck = lib.login("cskh"); CSKH = lib.hdr(ck)
TRIP = "e0017bde-c3ea-5f18-9f87-5981ba17cc2c"
created = []
out = {"load": {}, "race": {}}

def pct(xs, p):
    if not xs: return None
    xs = sorted(xs); k = (len(xs)-1)*p/100
    f = int(k); c = min(f+1, len(xs)-1)
    return round(xs[f] + (xs[f]-xs[f])*0 if f==c else xs[f]+(xs[c]-xs[f])*(k-f), 4)

def run_level(label, fn, n, conc):
    lat, errs, codes = [], 0, {}
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(fn) for _ in range(n)]
        for fu in as_completed(futs):
            dt, sc, ok = fu.result()
            lat.append(dt); codes[sc] = codes.get(sc,0)+1
            if not ok: errs += 1
    res = {"n": n, "concurrency": conc, "throughput_rps": round(n/sum(lat)*conc,2) if lat else 0,
           "p50": pct(lat,50), "p95": pct(lat,95), "p99": pct(lat,99),
           "max": round(max(lat),4) if lat else None, "errors": errs, "err_rate": round(errs/n,3), "codes": codes}
    breach = (res["p99"] and res["p99"]>5) or res["err_rate"]>0.10
    res["abort_threshold_breached"] = breach
    return res, breach

def read_once():
    t=time.time()
    try:
        r=httpx.get(f"{BASE}/cases",headers=CH,timeout=15)
        return time.time()-t, r.status_code, r.status_code==200
    except Exception as e:
        return time.time()-t, "EXC", False

def write_once():
    t=time.time()
    body={"title":lib.MARK+"load "+uuid.uuid4().hex[:8],"complaint":lib.MARK+"load write probe body",
          "category":"LOST_ITEM","trip_id":TRIP,"channel":"app","customer_evidence":[]}
    try:
        r=httpx.post(f"{BASE}/cases",json=body,headers=CH,timeout=20)
        ok=r.status_code==201
        if ok:
            try: created.append(r.json().get("id"))
            except Exception: pass
        return time.time()-t, r.status_code, ok
    except Exception:
        return time.time()-t, "EXC", False

# READ ramp
print("== READ ramp GET /cases ==")
for conc in (5,10,15,20):
    res,breach=run_level("read",read_once, n=conc*2, conc=conc)
    out["load"][f"read_c{conc}"]=res
    print(f"  c={conc}: p50={res['p50']} p95={res['p95']} p99={res['p99']} err={res['err_rate']} codes={res['codes']}")
    if breach:
        print("  !! threshold breached, stopping read ramp"); break
    time.sleep(1.0)

# WRITE ramp (bounded total writes)
print("== WRITE ramp POST /cases ==")
for conc in (5,10,15):
    res,breach=run_level("write",write_once, n=conc, conc=conc)
    out["load"][f"write_c{conc}"]=res
    print(f"  c={conc}: p50={res['p50']} p95={res['p95']} p99={res['p99']} err={res['err_rate']} codes={res['codes']}")
    if breach:
        print("  !! threshold breached, stopping write ramp"); break
    time.sleep(1.5)

# RACE 1: double-submit rating same trip concurrently
print("== RACE: concurrent rate_trip (ON CONFLICT upsert) ==")
def rate(score):
    t=time.time()
    r=httpx.patch(f"{BASE}/trips/{TRIP}/rating",headers=CH,timeout=20,
                  json={"rating":score,"comment":lib.MARK+f"race rating {score}","praises_driver":False})
    return r.status_code, (r.json() if r.headers.get("content-type","").startswith("application/json") else {})
with ThreadPoolExecutor(max_workers=2) as ex:
    f1=ex.submit(rate,2); f2=ex.submit(rate,5)
    r1=f1.result(); r2=f2.result()
after=httpx.get(f"{BASE}/trips/{TRIP}",headers=CH,timeout=20).json()
out["race"]["double_rating"]={"resp1":r1[0],"resp2":r2[0],"final_rating":after.get("rating"),
  "note":"ON CONFLICT(customer_id,trip_id) upsert => exactly one rating row, both requests 200, no duplicate/500"}
print("  ",out["race"]["double_rating"])

# RACE 2: concurrent claim of an OPEN cskh-task (one of my LOST_ITEM cases)
print("== RACE: concurrent cskh-task claim ==")
claim_case = created[0] if created else None
if claim_case:
    def claim():
        t=time.time()
        r=httpx.post(f"{BASE}/cases/{claim_case}/cskh-task/claim",headers=CSKH,timeout=20)
        return r.status_code, (r.json() if r.headers.get("content-type","").startswith("application/json") else {})
    with ThreadPoolExecutor(max_workers=2) as ex:
        c1=ex.submit(claim); c2=ex.submit(claim)
        rc1=c1.result(); rc2=c2.result()
    out["race"]["double_claim"]={"case":claim_case,"resp1":rc1[0],"resp2":rc2[0],
      "status1":(rc1[1] or {}).get("status"),"status2":(rc2[1] or {}).get("status"),
      "note":"UPDATE ... WHERE status IN (OPEN,CLAIMED) under case FOR UPDATE lock; serialized, no error"}
    print("  ",out["race"]["double_claim"])

out["_created_cases"]=created
print("\nCREATED:",len(created),"cases")
lib.save_evidence("02_load_race.json", out)
