"""P-143 dynamic load/latency ramp. stdlib only. Run: python -I load_test.py <base> <tokenfile>
Ramps concurrency over read + write surfaces, reports p50/p95/p99, throughput, error rate."""
import sys, json, time, statistics, threading, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

BASE = sys.argv[1]
TOKEN = open(sys.argv[2]).read().strip()

def call(method, path, body=None):
    h = {"Authorization": "Bearer " + TOKEN, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            resp.read(); return resp.status, time.perf_counter() - t0
    except urllib.error.HTTPError as e:
        e.read(); return e.code, time.perf_counter() - t0
    except Exception:
        return -1, time.perf_counter() - t0

def pct(xs, p):
    xs = sorted(xs); 
    if not xs: return 0.0
    k = (len(xs)-1)*p/100.0; f=int(k)
    return xs[f] if f+1>=len(xs) else xs[f]+(xs[f+1]-xs[f])*(k-f)

SURFACES = {
    "GET /invoices":         ("GET", "/api/v1/invoices", None),
    "GET /dashboard/summary":("GET", "/api/v1/dashboard/summary", None),
    "GET /auth/me":          ("GET", "/api/v1/auth/me", None),
    "GET /purchase-orders":  ("GET", "/api/v1/purchase-orders", None),
    "GET /vendors":          ("GET", "/api/v1/vendors", None),
}
LEVELS = [1,5,10,20,50]
REQ_PER_LEVEL = 200

print(f"# Load ramp @ {BASE}  ({time.strftime('%Y-%m-%d %H:%M:%S %z')})")
for name,(m,p,b) in SURFACES.items():
    print(f"\n## {name}")
    print(f"{'conc':>4} {'n':>4} {'ok%':>6} {'thr/s':>8} {'p50ms':>8} {'p95ms':>8} {'p99ms':>8} {'maxms':>8}")
    prev = None
    for c in LEVELS:
        lats=[]; codes=[]
        def one(_):
            s,d = call(m,p,b); lats.append(d*1000); codes.append(s)
        t0=time.perf_counter()
        with ThreadPoolExecutor(max_workers=c) as ex:
            list(ex.map(one, range(REQ_PER_LEVEL)))
        wall=time.perf_counter()-t0
        ok=sum(1 for s in codes if 200<=s<400)
        thr=REQ_PER_LEVEL/wall
        p50,p95,p99,mx=pct(lats,50),pct(lats,95),pct(lats,99),max(lats)
        knee=""
        if prev and p95>prev*2.0: knee=" <== knee (p95 >2x)"
        prev=p95
        print(f"{c:>4} {REQ_PER_LEVEL:>4} {100*ok/len(codes):>6.1f} {thr:>8.1f} {p50:>8.1f} {p95:>8.1f} {p99:>8.1f} {mx:>8.1f}{knee}")
