"""Battery #4 (rate limit) + #3 (caching). Controlled, low volume (Vercel-safe)."""
import importlib, sys, os, time, statistics
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(__file__))
C = importlib.import_module("02_common")

def rate_limit_probe(s):
    """Burst of 25 GET /hr/employees; look for any 429 / Retry-After. Also header-bypass sanity."""
    def one(i):
        t = time.time()
        r = s.get(f"{C.BASE}/hr/employees", timeout=C.TIMEOUT,
                  headers={"X-Forwarded-For": f"10.0.0.{i%250}", "X-Real-IP": f"10.0.0.{i%250}"})
        return r.status_code, round(time.time()-t,3)
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(one, range(25)))
    codes = [c for c,_ in res]
    return {"requests": len(res), "status_counts": {c: codes.count(c) for c in set(codes)},
            "any_429": 429 in codes, "max_s": max(t for _,t in res), "note": "X-Forwarded-For varied per req"}

def cache_probe(s):
    """Same identical file previewed twice. No request cache in code => both recompute (similar latency)."""
    data = (b"So tay chinh sach nghi phep benh vien An Khang danh cho nhan vien moi. "
            b"Moi nam nhan vien duoc nghi 12 ngay phep co huong luong. SECTEST-CACHE-PROBE") 
    r1 = C.preview(s, "cache_probe.txt", data, "text/plain")
    r2 = C.preview(s, "cache_probe.txt", data, "text/plain")
    return {"first": {"status": r1[0], "elapsed_s": r1[1], "title": r1[2].get("title") if isinstance(r1[2],dict) else None},
            "second": {"status": r2[0], "elapsed_s": r2[1], "title": r2[2].get("title") if isinstance(r2[2],dict) else None},
            "second_near_instant": r2[1] < 0.3,
            "interpretation": "no per-request/preview cache if both take comparable (LLM) time"}

def main():
    s = C.hr_session()
    rl = rate_limit_probe(s)
    print("RATE-LIMIT:", rl)
    ca = cache_probe(s)
    print("CACHE:", ca)
    C.save("02_rate_and_cache.json", {"rate_limit": rl, "cache": ca})

if __name__ == "__main__":
    main()
