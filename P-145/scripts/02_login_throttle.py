"""Battery #4 extension: /auth/login is unauthenticated; check for brute-force throttling/lockout.
Low volume (12 wrong-password attempts) to avoid flood; confirms no 429 and account not locked.
Compounds Finding-01 (shared guessable initial password)."""
import importlib, sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
C = importlib.import_module("02_common")
import requests
def main():
    codes=[]
    for i in range(12):
        r=requests.post(f"{C.BASE}/auth/login", json={"email": C.HR_EMAIL, "password": f"wrong-{i}"}, timeout=C.TIMEOUT)
        codes.append(r.status_code)
    # verify correct password still works right after (no lockout)
    r=requests.post(f"{C.BASE}/auth/login", json={"email": C.HR_EMAIL, "password": C.HR_PASS}, timeout=C.TIMEOUT)
    res={"wrong_attempts": len(codes), "status_counts": {c: codes.count(c) for c in set(codes)},
         "any_429": 429 in codes, "correct_after_fails_status": r.status_code,
         "locked_out": r.status_code != 200}
    print(res); C.save("02_login_throttle.json", res)
if __name__=="__main__": main()
