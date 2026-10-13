# [P-xxx] FINDING-NN: <tiêu đề ngắn>

- **Phân loại / Category:** <prompt-injection | permission-leak/IDOR | context-overflow | auth | injection | secret-leak | ssrf | rate-limit | khác>
- **Mã định danh (CWE/OWASP/CVE):** <vd CWE-639: Authorization Bypass Through User-Controlled Key; OWASP API1:2023 BOLA; OWASP LLM01:2025 Prompt Injection — kèm định nghĩa ngắn + ref link. Để trống nếu không có mã chuẩn tương ứng.>
- **Mức độ / Severity:** Critical | High | Medium | Low | Info
- **Thời gian phát hiện:** YYYY-MM-DD HH:MM (+07)
- **Link/endpoint:** <URL + METHOD path>
- **Tài khoản dùng:** <email/username : password hoặc token (nếu dùng)>
- **Luồng (flow):** <mô tả bước nghiệp vụ dẫn tới lỗ hổng>

## Mô tả
<lỗ hổng là gì, vì sao nguy hiểm>

## Cách tái hiện (repro)
<các bước / lệnh; trỏ tới scripts/NN_*.sh>

### Input
```
<request thật sự gửi đi>
```
### Output
```
<response nhận được chứng minh lỗ hổng>
```

## Tác động
<kẻ tấn công làm được gì>

## Khuyến nghị sửa
<fix cụ thể>

## Bằng chứng
- scripts/NN_*.sh
- evidences/NN_*.{json,txt,png}
