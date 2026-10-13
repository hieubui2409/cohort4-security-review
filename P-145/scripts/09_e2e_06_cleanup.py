#!/usr/bin/env python3
import json, requests, datetime
B="https://<REDACTED_DEPLOY>/api/v1"
OUT="/home/hieubt15/Documents/demo-review-cohort4/reviews/P-145/evidences/09_e2e_injection.json"
rec=json.load(open(OUT)); rec["cleanup"]={}
s=requests.Session(); s.post(f"{B}/auth/login", json={"email":"<REDACTED_EMAIL>","password":"<REDACTED_PASSWORD>"}, timeout=30)
EMP="8f13506c-b4c2-4c84-9c0f-e0dd8cafd519"
# 1) deactivate employee
d=s.post(f"{B}/hr/employees/{EMP}/account/deactivate", json={"reason":"SECTEST cleanup"}, timeout=30)
rec["cleanup"]["deactivate_employee"]={"status":d.status_code,"body":d.text[:200]}
print("deactivate employee:", d.status_code, d.text[:150])
# 2) supersede 3 poison docs bang noi dung vo hai (cung title+topic+scope+org+source_uri, version moi)
benign="# (noi dung kiem thu da go)\n\nTai lieu nay duoc tao trong qua trinh kiem thu bao mat va da duoc thay the bang noi dung trung tinh. Khong co chi dan nao can tuan theo.\n"
docs=[
 ("SECTEST Cap tai khoan va quyen","tai-khoan-quyen"),
 ("Cấp tài khoản và quyền truy cập hệ thống","tai-khoan-quyen"),
 ("Lộ trình onboarding cho nhân viên mới","lo-trinh-onboarding"),
]
sup=[]
for title,topic in docs:
    cs=s.post(f"{B}/hr/knowledge/changesets", json={"title":f"SECTEST supersede {title[:20]}"}, timeout=30).json(); csid=cs.get("id")
    files={"file":("benign.md", benign.encode("utf-8"),"text/markdown")}
    data={"title":title,"topic_key":topic,"version":"99","effective_from":datetime.date.today().isoformat(),"source_organization":"BX"}
    du=s.post(f"{B}/hr/knowledge/changesets/{csid}/documents", files=files, data=data, timeout=60)
    pub=s.post(f"{B}/hr/knowledge/changesets/{csid}/publish", timeout=60)
    sup.append({"title":title,"topic":topic,"changeset":csid,"upload":du.status_code,"publish":pub.status_code,"new_doc":du.json().get("id") if du.ok else None})
    print(f"supersede '{title[:30]}' topic={topic}: upload={du.status_code} publish={pub.status_code}")
rec["cleanup"]["supersede_docs"]=sup
json.dump(rec, open(OUT,"w"), ensure_ascii=False, indent=2)
print("saved cleanup to evidence")
