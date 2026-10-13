import sys, json, time, threading, urllib.request, urllib.error, uuid
from concurrent.futures import ThreadPoolExecutor
BASE, TOK, SRC = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
tpl=open(SRC,'rb').read()
def pct(xs,p):
    xs=sorted(xs); k=(len(xs)-1)*p/100.0; f=int(k)
    return xs[f] if f+1>=len(xs) else xs[f]+(xs[f+1]-xs[f])*(k-f)
def upload(_):
    marker=('SECTEST-LOAD-'+uuid.uuid4().hex).encode()
    data=tpl.replace(b'<SHDon>0000501</SHDon>', b'<SHDon>'+marker+b'</SHDon>')
    boundary='----b'+uuid.uuid4().hex
    body=b'--'+boundary.encode()+b'\r\nContent-Disposition: form-data; name="files"; filename="l.xml"\r\nContent-Type: application/xml\r\n\r\n'+data+b'\r\n--'+boundary.encode()+b'--\r\n'
    h={"Authorization":"Bearer "+TOK,"Content-Type":"multipart/form-data; boundary="+boundary}
    r=urllib.request.Request(BASE+"/api/v1/invoices/upload", data=body, method="POST", headers=h)
    t0=time.perf_counter()
    try:
        with urllib.request.urlopen(r, timeout=60) as resp: resp.read(); return resp.status, time.perf_counter()-t0
    except urllib.error.HTTPError as e: e.read(); return e.code, time.perf_counter()-t0
    except Exception: return -1, time.perf_counter()-t0
print("# WRITE load ramp POST /invoices/upload (unique XML)", time.strftime('%H:%M:%S %z'))
print(f"{'conc':>4} {'n':>4} {'2xx%':>6} {'thr/s':>7} {'p50ms':>8} {'p95ms':>8} {'p99ms':>8}")
for c in [1,5,10,20]:
    n=40; lats=[]; codes=[]
    def one(i):
        s,d=upload(i); lats.append(d*1000); codes.append(s)
    t0=time.perf_counter()
    with ThreadPoolExecutor(max_workers=c) as ex: list(ex.map(one,range(n)))
    wall=time.perf_counter()-t0
    ok=sum(1 for s in codes if 200<=s<300)
    print(f"{c:>4} {n:>4} {100*ok/n:>6.1f} {n/wall:>7.1f} {pct(lats,50):>8.1f} {pct(lats,95):>8.1f} {pct(lats,99):>8.1f}")
