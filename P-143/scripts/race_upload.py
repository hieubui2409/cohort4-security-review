import sys, json, time, threading, urllib.request, urllib.error, uuid
BASE, TOK, FP = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
content=open(FP,'rb').read(); N=10
def upload(data):
    boundary='----sectest'+uuid.uuid4().hex
    body=b'--'+boundary.encode()+b'\r\nContent-Disposition: form-data; name="files"; filename="dup.xml"\r\nContent-Type: application/xml\r\n\r\n'+data+b'\r\n--'+boundary.encode()+b'--\r\n'
    h={"Authorization":"Bearer "+TOK,"Content-Type":"multipart/form-data; boundary="+boundary}
    r=urllib.request.Request(BASE+"/api/v1/invoices/upload", data=body, method="POST", headers=h)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp: return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
    except Exception as ex: return -1, str(ex)
bar=threading.Barrier(N); res=[]; lock=threading.Lock()
def w(i):
    bar.wait(); s,b=upload(content)
    created=None; dup=None
    try:
        j=json.loads(b); f=(j.get('files') or [{}])[0]
        created=f.get('invoice_id'); dup=f.get('duplicate_of')
        err=(j.get('error') or {}).get('code') if isinstance(j.get('error'),dict) else f.get('error')
    except: err=b[:80]
    with lock: res.append((i,s,created,dup,err))
ts=[threading.Thread(target=w,args=(i,)) for i in range(N)]
for t in ts:t.start()
for t in ts:t.join()
from collections import Counter
print("# concurrent duplicate-upload race N=",N, time.strftime('%H:%M:%S %z'))
newinv=[c for _,_,c,d,_ in res if c and not d]
print("distinct NEW invoice_ids (duplicate_of null):", len(set(newinv)), set(newinv))
print("status counts:", dict(Counter(s for _,s,_,_,_ in res)))
for i,s,c,d,e in sorted(res): print(f"  {i:>2} http={s} inv={c} dup_of={d} err={e}")
