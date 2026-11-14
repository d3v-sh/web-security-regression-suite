# Web Security Regression Suite Report

- **Target Environment:** `http://localhost:3000`
- **Execution Timestamp:** `2026-11-14T22:06:58+05:30`

| Test ID | Category | Test Case | Expected Secure Result | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| WEB-T01 | Input Validation | Send a 500-character display_name to local fixture | Request rejected with 400; no crash; no stack trace. | `HTTP 400 (500-char payload accepted=false, stack_trace=false)` | PASS |
| WEB-T02 | Output Encoding | Submit harmless text containing <tag> to local fixture | Output is encoded as text; no script execution. | `HTTP 200 (/main.js bypassSecurityTrustHtml_sink=true)` | **FAIL** |
| WEB-T03 | Access Control | Use viewer role against protected admin fixture | Access denied; no protected data returned. | `HTTP 403 (response_bytes=50)` | PASS |
| WEB-T04 | Info Exposure | Request public health endpoint | Only approved status fields are returned. | `HTTP 200, payload={"status":"ok"}` | PASS |
| HDR-01 | Security Headers | Verify Content-Security-Policy response header | Restrictive CSP header present | `default-src 'self';script-src 'self' 'unsafe-inline' 'unsafe-eval';style-src 'self' 'unsafe-inline';img-src 'self' data: blob:;connect-src 'self';frame-ancestors 'self'` | PASS |
| HDR-02 | Security Headers | Verify X-Content-Type-Options response header | nosniff directive present | `nosniff` | PASS |
| HDR-03 | Security Headers | Verify X-Frame-Options response header | DENY or SAMEORIGIN present | `SAMEORIGIN` | PASS |
| HDR-04 | Security Headers | Verify Referrer-Policy response header | Strict referrer policy header present | `strict-origin-when-cross-origin` | PASS |
| CK-01 | Cookie Flags | Inspect Set-Cookie attributes on POST /rest/user/login | Session cookies set with HttpOnly, Secure, and explicit SameSite flags | `No Set-Cookie headers issued on login (token stored client-side only)` | PASS |
