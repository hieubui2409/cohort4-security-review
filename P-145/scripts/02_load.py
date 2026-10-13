"""Battery #7: light load/contention. Ramp concurrent GET /hr/employees (read) + a few
light writes (POST /hr/knowledge/changesets labelled SECTEST-). p50/p95/p99 + knee. Vercel-safe.
Records created changeset IDs for cleanup.
"""
import importlib, sys, os, time, statistics
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(__file__))
C = importlib.import_module("02_common")

def pct(xs, p):
    xs = sorted(xs); k = (len(xs)-1)*p/100.0
    import math; f=math.floor(k); c=math.ceil(k)
    if f==c: return round(xs[int(k)],3)
    return round(xs[f]+(xs[c]-xs[f])*(k-f),3)

def ramp(s):
    levels = [1,5,10,20]
    out = []
    def get(_):
        t=time.time(); r=s.get(f"{C.BASE}/hr/employees", timeout=C.TIMEOUT); return r.status_code, time.time()-t
    for conc in levels:
        n = conc*3
        with ThreadPoolExecutor(max_workers=conc) as ex:
            res = list(ex.map(get, range(n)))
        lat = [t for _,t in res]; codes=[c for c,_ in res]
        out.append({"concurrency": conc, "requests": n,
                    "ok": sum(1 for c in codes if c==200), "non200": [c for c in codes if c!=200],
                    "p50": pct(lat,50), "p95": pct(lat,95), "p99": pct(lat,99),
                    "min": round(min(lat),3), "max": round(max(lat),3)})
        print(out[-1])
        time.sleep(1)
    return out

def writes(s):
    created=[]
    def mk(i):
        t=time.time()
        r=s.post(f"{C.BASE}/hr/knowledge/changesets", json={"title": f"SECTEST-load-{int(time.time())}-{i}"}, timeout=C.TIMEOUT)
        el=round(time.time()-t,3)
        cid=None
        try: cid=r.json().get("id")
        except Exception: pass
        return {"status": r.status_code, "elapsed_s": el, "id": cid}
    # 5 concurrent writes interleaved with reads (contention)
    def rd(_): 
        r=s.get(f"{C.BASE}/hr/employees", timeout=C.TIMEOUT); return r.status_code
    with ThreadPoolExecutor(max_workers=10) as ex:
        wf=[ex.submit(mk,i) for i in range(5)]
        rf=[ex.submit(rd,i) for i in range(10)]
        wres=[f.result() for f in wf]; rres=[f.result() for f in rf]
    for w in wres:
        if w["id"]: created.append(w["id"])
    return {"writes": wres, "concurrent_reads_ok": sum(1 for c in rres if c==200), "created_ids": created}

def main():
    s=C.hr_session()
    r=ramp(s)
    w=writes(s)
    print("WRITES:", w)
    C.save("02_load.json", {"ramp": r, "write_contention": w})
    if w["created_ids"]:
        print("CREATED CHANGESETS (cleanup):")
        for i in w["created_ids"]: print("  ", i)

if __name__ == "__main__":
    main()
