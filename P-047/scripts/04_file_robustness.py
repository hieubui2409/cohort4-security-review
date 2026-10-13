#!/usr/bin/env python3
"""P-047 MoveInMate — Battery mở rộng (phần B): FILE ROBUSTNESS.

Endpoint: /agent/form-from-files (multi-file, resident) và /vehicles/extract (1 ảnh).
Kiểm: giới hạn kích thước/kiểu, zip-bomb nhỏ, PDF malformed, MIME sai, tên file traversal,
decompression bomb; mọi lỗi phải AN TOÀN (không 500 lộ stack), đúng mã lỗi.

Phần lớn case lỗi xảy ra TRƯỚC khi reserve OCR budget => không tốn quota. Không phá huỷ.
"""
import io
import json
import time
import zipfile
import urllib.request
import urllib.error

BASE = "https://<REDACTED_DEPLOY>/api/v1"
EVID = "/home/hieubt15/Documents/demo-review-cohort4/reviews/P-047/evidences/04_file_robustness.json"
BOUNDARY = "----P047BatteryBoundary"

results = {"base": BASE, "started": time.strftime("%Y-%m-%d %H:%M:%S"), "cases": []}


def login(u, p):
    data = json.dumps({"username": u, "password": p}).encode()
    req = urllib.request.Request(BASE + "/auth/login", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())["access_token"]


def multipart(fields, files):
    """fields: list[(name,value)]; files: list[(name,filename,content_bytes,ctype)]."""
    body = io.BytesIO()
    for name, value in fields:
        body.write(f"--{BOUNDARY}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.write(f"{value}\r\n".encode())
    for name, filename, content, ctype in files:
        body.write(f"--{BOUNDARY}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode())
        body.write(f"Content-Type: {ctype}\r\n\r\n".encode())
        body.write(content)
        body.write(b"\r\n")
    body.write(f"--{BOUNDARY}--\r\n".encode())
    return body.getvalue()


def post_files(path, token, fields, files, timeout=90):
    data = multipart(fields, files)
    headers = {"Authorization": "Bearer " + token,
               "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
               "Accept": "application/json"}
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method="POST")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            b = r.read().decode("utf-8", "replace"); s = r.status
    except urllib.error.HTTPError as e:
        b = e.read().decode("utf-8", "replace"); s = e.code
    except Exception as e:  # noqa: BLE001
        return -1, round(time.monotonic() - t0, 2), f"EXC {type(e).__name__}: {e}"
    el = round(time.monotonic() - t0, 2)
    try:
        p = json.loads(b)
    except ValueError:
        p = b[:500]
    return s, el, p


def record(name, path, status, elapsed, resp, expect, safe_note=""):
    body_str = resp if isinstance(resp, str) else json.dumps(resp, ensure_ascii=False)
    leaked = any(k in body_str for k in ("Traceback", "File \"/", "line ", "sqlalchemy", "/home/", "/app/", "/etc/passwd"))
    is500 = isinstance(status, int) and status >= 500
    results["cases"].append({
        "name": name, "path": path, "status": status, "elapsed_s": elapsed,
        "expected": expect, "resp": body_str[:400],
        "no_500": not is500, "no_stack_leak": not leaked, "safe": (not is500 and not leaked),
        "safe_note": safe_note,
    })
    print(f"  {name:<34} HTTP {status} ({elapsed}s) safe={not is500 and not leaked}")


def make_zip_bomb_docx(uncompressed_mb=30):
    """DOCX hợp lệ cấu trúc nhưng word/document.xml giải nén > 25MB (nén nhỏ)."""
    buf = io.BytesIO()
    big = ("<w:p><w:r><w:t>" + "A" * 1000 + "</w:t></w:r></w:p>") * (uncompressed_mb * 1000)
    xml = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
           'wordprocessingml/2006/main"><w:body>' + big + "</w:body></w:document>")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", xml)
    return buf.getvalue()


print("Login resident...")
TOKEN = login("user", "<REDACTED_PASSWORD>")
VALID_TXT = "Giay dang ky xe: Nguyen Van A, bien so 29-A1 123.45".encode()

print("\n[/agent/form-from-files] robustness")
P = "/agent/form-from-files"
F = [("conversation_id", "frob-" + str(int(time.time()))), ("message", "Doc giay to")]

# 1. Count limit (MAX_FILES=4) -> 5 files
files5 = [("files", f"f{i}.txt", VALID_TXT, "text/plain") for i in range(5)]
s, e, r = post_files(P, TOKEN, F, files5); record("count>4 (MAX_FILES)", P, s, e, r, "422 attachment_count_invalid")

# 2. Unsupported type
s, e, r = post_files(P, TOKEN, F, [("files", "evil.exe", b"MZ\x90\x00payload", "application/octet-stream")])
record("unsupported ext .exe", P, s, e, r, "415 unsupported_file_type")

# 3. MIME mismatch: .png content not PNG
s, e, r = post_files(P, TOKEN, F, [("files", "pic.png", b"this is not a png at all", "image/png")])
record("fake .png (bad signature)", P, s, e, r, "422 invalid_image")

# 4. Malformed PDF (not %PDF)
s, e, r = post_files(P, TOKEN, F, [("files", "doc.pdf", b"not really a pdf content here", "application/pdf")])
record("malformed .pdf (no %PDF)", P, s, e, r, "422 invalid_pdf")

# 5. %PDF header but corrupt body
s, e, r = post_files(P, TOKEN, F, [("files", "corrupt.pdf", b"%PDF-1.4\n%garbage\x00\x01\x02 broken", "application/pdf")])
record("corrupt .pdf (%PDF then junk)", P, s, e, r, "422 invalid_pdf")

# 6. Zip bomb DOCX (uncompressed > 25MB)
bomb = make_zip_bomb_docx(30)
s, e, r = post_files(P, TOKEN, F, [("files", "bomb.docx", bomb, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")])
record(f"zip-bomb .docx ({len(bomb)} B->~30MB)", P, s, e, r, "422 docx_too_large", "nén nhỏ, giải nén >25MB")

# 7. Random bytes as .docx (BadZipFile)
s, e, r = post_files(P, TOKEN, F, [("files", "junk.docx", b"\x50\x4b\x03\x04 not a zip really", "application/octet-stream")])
record("not-a-zip .docx", P, s, e, r, "422 invalid_docx")

# 8. Oversized doc > 8MB (single) but < 16MB total
big9 = b"x" * (9 * 1024 * 1024)
s, e, r = post_files(P, TOKEN, F, [("files", "big.txt", big9, "text/plain")])
record("doc > 8MB", P, s, e, r, "413 file_too_large")

# 9. Oversized total > 16MB (two 9MB txt)
s, e, r = post_files(P, TOKEN, F, [("files", "a.txt", big9, "text/plain"), ("files", "b.txt", big9, "text/plain")], timeout=120)
record("total > 16MB", P, s, e, r, "413 attachments_too_large")

# 10. Filename path traversal -> safe_filename must strip path
s, e, r = post_files(P, TOKEN, F, [("files", "../../../../etc/passwd.png", b"still not a png", "image/png")])
record("traversal filename .png", P, s, e, r, "422 invalid_image (name sanitized)", "resp phải nêu tên đã strip, không có đường dẫn")

# 11. Empty filename / weird
s, e, r = post_files(P, TOKEN, F, [("files", "", b"hello", "application/octet-stream")])
record("empty filename", P, s, e, r, "4xx (no ext -> unsupported)")

print("\n[/vehicles/extract] robustness")
V = "/vehicles/extract"
FV = [("consent", "true")]
# v1. Non-image doc
s, e, r = post_files(V, TOKEN, FV, [("document", "x.txt", VALID_TXT, "text/plain")])
record("vehicle: txt not image", V, s, e, r, "422 vehicle_image_required / unsupported")
# v2. Oversized image > 5MB (fake png signature + padding)
bigpng = b"\x89PNG\r\n\x1a\n" + b"\x00" * (6 * 1024 * 1024)
s, e, r = post_files(V, TOKEN, FV, [("document", "big.png", bigpng, "image/png")], timeout=120)
record("vehicle: png > 5MB", V, s, e, r, "413 file_too_large")
# v3. consent=false
s, e, r = post_files(V, TOKEN, [("consent", "false")], [("document", "x.png", b"\x89PNG\r\n\x1a\n", "image/png")])
record("vehicle: no consent", V, s, e, r, "400 image_processing_consent_required")
# v4. traversal + bad image
s, e, r = post_files(V, TOKEN, FV, [("document", "../../root/.ssh/id_rsa.jpg", b"\xff\xd8\xff bad", "image/jpeg")])
record("vehicle: traversal filename", V, s, e, r, "422 invalid image (name sanitized)")

results["ended"] = time.strftime("%Y-%m-%d %H:%M:%S")
unsafe = [c["name"] for c in results["cases"] if not c["safe"]]
results["summary"] = {"total": len(results["cases"]),
                      "all_safe_no_500_no_leak": not unsafe,
                      "unsafe_cases": unsafe}
with open(EVID, "w") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)
print(f"\nSaved -> {EVID}")
print("ALL SAFE (no 500 / no stack leak):", not unsafe, "| unsafe:", unsafe)
