import sys, json, time, threading, urllib.request, urllib.error
from collections import Counter
BASE=sys.argv[1]
def login(email, pw):
    h={"Content-Type":"application/json","Accept":"application/json"}
    r=urllib.request.Request(BASE+"/api/v1/auth/login", data=json.dumps({"email":email,"password":pw}).encode(), method="POST", headers=h)
    t0=time.perf_counter()
    try:
        with urllib.request.urlopen(r, timeout=30) as resp: return resp.status, time.perf_counter()-t0
    except urllib.error.HTTPError as e:
        b=e.read().decode(); 
        try: code=json.loads(b)["error"]["code"]
        except: code=""
        return (e.code, code), time.perf_counter()-t0
    except Exception as ex: return -1, time.perf_counter()-t0

print("### A) Rate-limit probe: 120 rapid logins, bogus non-existent email")
codes=[]; t0=time.perf_counter()
for i in range(120):
    s,_=login("nobody-%d@nope.vn"%(i%3), "wrong"); codes.append(s)
print("elapsed %.2fs"%(time.perf_counter()-t0), "status counts:", dict(Counter(codes)))
print("  -> any 429 (rate limited)?", any((isinstance(s,tuple) and s[0]==429) or s==429 for s in codes))

print("\n### B) Per-account lockout (sequential): <REDACTED_EMAIL> wrong password x8")
for i in range(8):
    s,_=login("<REDACTED_EMAIL>","wrongpass"); print(f"  attempt {i+1}: {s}")

print("\n### C) TOCTOU race on failure counter: 15 concurrent wrong logins for a FRESH account")
# use second fresh victim seeded below
EMAIL=sys.argv[2]
res=[]; lock=threading.Lock(); bar=threading.Barrier(15)
def w(i):
    bar.wait(); s,_=login(EMAIL,"wrongpass")
    with lock: res.append(s)
ts=[threading.Thread(target=w,args=(i,)) for i in range(15)]
for t in ts:t.start()
for t in ts:t.join()
print("  concurrent results:", dict(Counter(res)))
# now check: is correct password accepted or locked after the burst?
s,_=login(EMAIL, "sectest-Passw0rd-7e1a")
print("  correct-password login AFTER burst:", s, "(423/409 LOCKED => lockout held; 200 => not locked)")
