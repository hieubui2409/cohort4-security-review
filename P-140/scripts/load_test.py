#!/usr/bin/env python3
"""P-140 load test: ramp concurrency, read (/api/v1/status) + write (/api/v1/chat SECTEST-).
Run OUTSIDE repo: python3 -I load_test.py <base_url>. Stdlib only.
Note: /chat is stateless (no DB/persistence) -> no server-side records to clean up."""
import sys, time, json, urllib.request, urllib.error, threading, statistics
BASE = sys.argv[1] if len(sys.argv)>1 else "http://127.0.0.1:8140"

def one(path, body=None):
    data=json.dumps(body).encode() if body is not None else None
    h={"Content-Type":"application/json"} if data else {}
    r=urllib.request.Request(BASE+path,data=data,headers=h,method=("POST" if data else "GET"))
    t0=time.time()
    try:
        with urllib.request.urlopen(r,timeout=30) as resp:
            resp.read(); return (time.time()-t0)*1000, resp.status
    except urllib.error.HTTPError as e:
        e.read(); return (time.time()-t0)*1000, e.code
    except Exception as e:
        return (time.time()-t0)*1000, "ERR"

def worker(n, path, body, out, idx):
    lat=[]; ok=0; bad=0
    for i in range(n):
        ms,st=one(path, body(i) if body else None)
        lat.append(ms)
        if st==200: ok+=1
        else: bad+=1
    out[idx]=(lat,ok,bad)

def run(label, conc, per, path, body=None):
    out=[None]*conc; ths=[]
    t0=time.time()
    for i in range(conc):
        t=threading.Thread(target=worker,args=(per,path,body,out,i)); ths.append(t); t.start()
    for t in ths: t.join()
    wall=time.time()-t0
    lat=[x for o in out for x in o[0]]; ok=sum(o[1] for o in out); bad=sum(o[2] for o in out)
    lat.sort(); n=len(lat)
    pct=lambda p: lat[min(n-1,int(p/100*n))]
    total=ok+bad
    rps=total/wall if wall else 0
    print(f"  conc={conc:>3} total={total:>5} ok={ok:>5} bad={bad:>4} "
          f"rps={rps:7.1f} p50={pct(50):7.1f} p95={pct(95):7.1f} p99={pct(99):7.1f} max={lat[-1]:7.1f} wall={wall:.2f}s")
    return rps, pct(50), pct(95), pct(99)

print("="*70); print("P-140 LOAD TEST @",BASE,time.strftime("%Y-%m-%d %H:%M:%S%z")); print("="*70)
sect=lambda i: {"message":f"SECTEST-load-{threading.get_ident()}-{i}"}

print("\n-- READ load: GET /api/v1/status (ramp) --")
rr=[]
for c in (1,5,10,20,35,50):
    rr.append((c,)+run("read",c,40,"/api/v1/status"))
print("\n-- WRITE load: POST /api/v1/chat (SECTEST-, ramp) --")
wr=[]
for c in (1,5,10,20,35,50):
    wr.append((c,)+run("write",c,40,"/api/v1/chat",sect))

def knee(rows):
    # knee ~ where rps stops rising / p99 jumps
    best=max(rows,key=lambda r:r[1]); return best
print("\nREAD peak rps row (conc,rps,p50,p95,p99):", knee(rr))
print("WRITE peak rps row (conc,rps,p50,p95,p99):", knee(wr))
print("\nNOTE: /chat persists nothing (no DB) -> SECTEST- payloads leave no server-side records; nothing to clean up.")
