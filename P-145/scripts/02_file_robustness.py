"""Battery #5 (TRỌNG TÂM): file robustness via POST /hr/knowledge/preview (read-only, no DB write).
Malformed PDF/DOCX, zip bomb, nested/traversal/encrypted zip, >5MB, MIME mismatch, >50 members,
traversal filename. Assert: fail-safe (no 500/stacktrace, no hang, bounded), proper 4xx.
"""
import importlib, sys, os
sys.path.insert(0, os.path.dirname(__file__))
C = importlib.import_module("02_common")
FIX = "/tmp/claude-1000/-home-hieubt15-Documents-demo-review-cohort4/89e739cb-2232-49ef-9048-a9a0cec0ca34/scratchpad/fix"

def f(n): return open(os.path.join(FIX, n), "rb").read()

# (label, filename-sent, fixture, content-type, expectation)
CASES = [
    ("valid_txt_baseline",       "policy.txt",      "good_small.txt", "text/plain", "200 ok"),
    ("empty_pdf",                "empty.pdf",       "empty.pdf",      "application/pdf", "4xx empty"),
    ("malformed_pdf",            "bad.pdf",         "malformed.pdf",  "application/pdf", "4xx unreadable"),
    ("truncated_pdf",            "trunc.pdf",       "truncated.pdf",  "application/pdf", "4xx"),
    ("corrupt_docx",             "bad.docx",        "corrupt.docx",   "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "4xx"),
    ("not_a_zip",                "fake.zip",        "not_a_zip.zip",  "application/zip", "4xx not zip"),
    ("zip_bomb_ratio",           "bomb.zip",        "zipbomb.zip",    "application/zip", "4xx bomb/oversize member"),
    ("zip_traversal",            "trav.zip",        "traversal.zip",  "application/zip", "4xx traversal"),
    ("zip_nested",               "nest.zip",        "nested.zip",     "application/zip", "4xx nested"),
    ("zip_encrypted",            "enc.zip",         "encrypted.zip",  "application/zip", "4xx encrypted"),
    ("zip_many_members",         "many.zip",        "many_members.zip","application/zip", "4xx >50 or ok"),
    ("over_5mb_txt",             "huge.txt",        "big_over.txt",   "text/plain", "4xx oversize"),
    ("under_5mb_txt",            "large.txt",       "big_under.txt",  "text/plain", "200 ok bounded"),
    ("mime_png_as_pdf",          "photo.pdf",       "image_as.pdf",   "application/pdf", "4xx (magic != pdf)"),
    ("mime_text_as_pdf",         "note.pdf",        "text_as.pdf",    "application/pdf", "4xx"),
    ("filename_traversal",       "../../../etc/passwd.pdf", "malformed.pdf", "application/pdf", "4xx, no path escape"),
]

def main():
    s = C.hr_session()
    results = []
    for label, sent_name, fx, ct, expect in CASES:
        try:
            data = f(fx)
        except FileNotFoundError:
            results.append({"case": label, "skipped": "fixture missing"}); continue
        st, el, body = C.preview(s, sent_name, data, ct)
        msg = ""
        if isinstance(body, dict):
            msg = body.get("error", {}).get("message") or ("blocked=%s title=%s" % (body.get("blocked"), str(body.get("title"))[:40]))
        else:
            msg = str(body)[:200]
        stack = isinstance(body, str) and ("Traceback" in body or "File \"" in body)
        results.append({"case": label, "sent_filename": sent_name, "bytes": len(data),
                        "status": st, "elapsed_s": el, "expectation": expect,
                        "server_msg": msg, "stacktrace_leaked": bool(stack),
                        "is_500": st == 500})
        print(f"{label:24s} -> {st}  {el}s  {msg[:70]}")
    summary = {"total": len(results),
               "http_500": sum(1 for r in results if r.get("is_500")),
               "stacktrace_leaks": sum(1 for r in results if r.get("stacktrace_leaked")),
               "max_elapsed_s": max((r.get("elapsed_s",0) for r in results), default=0)}
    C.save("02_file_robustness.json", {"summary": summary, "results": results})
    print("SUMMARY", summary)

if __name__ == "__main__":
    main()
