import sys, json, time, threading, urllib.request, urllib.error
BASE, KTT, INV = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
N=12
def call(path, body):
    h={"Authorization":"Bearer "+KTT,"Content-Type":"application/json","Accept":"application/json"}
    r=urllib.request.Request(BASE+path, data=json.dumps(body).encode(), method="POST", headers=h)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp: return resp.status, resp.read().decode()[:160]
    except urllib.error.HTTPError as e: return e.code, e.read().decode()[:160]
    except Exception as ex: return -1, str(ex)[:160]
barrier=threading.Barrier(N); res=[]; lock=threading.Lock()
def w(i):
    barrier.wait()
    if i%2==0: s,b=call(f"/api/v1/invoices/{INV}/approve",{"level":2})
    else:      s,b=call(f"/api/v1/invoices/{INV}/reject",{"reason":"SECTEST mixed race"})
    with lock: res.append((i,"APPROVE" if i%2==0 else "REJECT",s,b))
ts=[threading.Thread(target=w,args=(i,)) for i in range(N)]
for t in ts: t.start()
for t in ts: t.join()
from collections import Counter
print("# mixed approve(L2)/reject race N=",N," invoice=",INV, time.strftime('%H:%M:%S %z'))
print("status counts:", dict(Counter((a,s) for _,a,s,_ in res)))
for i,a,s,b in sorted(res): print(f"  {i:>2} {a:>7} {s} {b[:110]}")
