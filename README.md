# Web Security Regression Suite



A standalone Go web security regression suite (`net/http`, zero external dependencies). `regression_suite.go` reads test cases from `fixtures/web_retest_cases.csv` and runs **9 automated security checks** against an isolated local instance of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) at `http://localhost:3000`.

The suite was used to retest manual findings after patching the Juice Shop source. Result: **3 passed, 6 failed → 8 passed, 1 failed**.

See [`LEARNING_JOURNAL.md`](LEARNING_JOURNAL.md) for concepts learned and two troubleshooting walkthroughs.

---

## Safe Scope & Ethics

- All manual testing, source-code patches, and automated checks ran **only** against an isolated, local OWASP Juice Shop instance (`http://localhost:3000`).
- Only synthetic test accounts (`regtest_*@local.test`, `gamer@game.com`) and dummy payloads were used.
- **No external or production systems were tested.**
- Do not point this suite at any system you do not own or have explicit written permission to test.

---

## Repository Structure

```
web-security-regression-suite/
├── regression_suite.go          # Test runner (Go, stdlib only)
├── fixtures/
│   └── web_retest_cases.csv     # Test case definitions
├── fixes/                       # Patched Juice Shop files / diffs
├── reports/                     # Before/after run output
├── evidence/
│   ├── before/                  # Pre-fix evidence (Burp captures, suite output)
│   └── after/                   # Post-fix evidence
├── LEARNING_JOURNAL.md
└── README.md
```

---

## Prerequisites

- **Go 1.21+** (`go version`)
- **OWASP Juice Shop** running locally on `http://localhost:3000`
  - Source install is required to reproduce the fixes (patches target `.ts` files). See the [Juice Shop repository](https://github.com/juice-shop/juice-shop).

## Installation

```bash
# 1. Clone this repository
git clone https://github.com/d3v-sh/web-security-regression-suite web-security-regression-suite
cd web-security-regression-suite

# 2. Verify Go toolchain
go version        # must be 1.21 or newer

# 3. Start local Juice Shop (separate terminal, from the Juice Shop source directory)
npm install
npm start         # serves http://localhost:3000

# 4. Confirm the target is up
curl -I http://localhost:3000
```

No `go get` is needed; the suite has no external dependencies.

## Usage

```bash
# Run directly
go run regression_suite.go

# Or build a binary
go build -o regression_suite regression_suite.go
./regression_suite

# Save output as a report
go run regression_suite.go | tee reports/run_$(date +%Y%m%d_%H%M%S).txt
```

The suite expects `fixtures/web_retest_cases.csv` relative to the working directory, so run from the repository root.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed |
| `1`  | One or more checks failed |

After remediation the suite exits non-zero by design: `WEB-T02` remains an intentionally unpatched failure (see below).

---

## Test Cases

| ID | Category | Check |
|----|----------|-------|
| `WEB-T01` | Input validation | `POST /profile` with a 500-char `username` (`Cookie: token=<jwt>`) |
| `WEB-T02` | Output encoding / DOM XSS | `/main.js` contains Angular `DomSanitizer.bypassSecurityTrustHtml()` sink |
| `WEB-T03` | Role-based access control | `GET /api/Users` with a low-privilege customer JWT |
| `WEB-T04` | Information exposure | Unauthenticated `GET /rest/admin/application-version` |
| `HDR-01` | Security headers | `Content-Security-Policy` present on `GET /` |
| `HDR-02` | Security headers | `X-Content-Type-Options: nosniff` |
| `HDR-03` | Security headers | `X-Frame-Options: SAMEORIGIN` |
| `HDR-04` | Security headers | `Referrer-Policy` present on `GET /` |
| `CK-01` | Cookie / session flags | `POST /rest/user/login` cookie flag check |

---

## Before vs. After Remediation

**Before: 3 passed, 6 failed → After: 8 passed, 1 failed**

| ID | Before | Fix | Patched file | After |
|----|--------|-----|--------------|-------|
| `WEB-T01` | `FAIL`: `HTTP 302`, 500-char payload accepted | Server-side type and length check (1–50 chars) before `UserModel.findByPk(...)`; returns `400` | `routes/updateUserProfile.ts` | `PASS`: `HTTP 400`, `accepted=false, stack_trace=false` |
| `WEB-T02` | `FAIL`: `HTTP 200`, `bypassSecurityTrustHtml_sink=true` | **Not patched** (scope boundary: requires Angular frontend rebuild via `ng build`) | n/a | `FAIL`: unchanged |
| `WEB-T03` | `FAIL`: `HTTP 200`, 13976 bytes of user records leaked | Admin role check (`user.data.role !== 'admin'`) in the `autoModels` loop before `finale.resource` mounts `/api/Users` and `/api/Users/:id`; `POST /api/Users` kept public for registration | `server.ts` | `PASS`: `HTTP 403`, `response_bytes=50` |
| `WEB-T04` | `FAIL`: `HTTP 200`, `{"version":"20.4.0-SNAPSHOT"}` | `retrieveAppVersion()` returns `{"status":"ok"}` | `routes/appVersion.ts` | `PASS`: `HTTP 200`, `{"status":"ok"}` |
| `HDR-01` | `FAIL`: missing header | `helmet.contentSecurityPolicy(...)` | `server.ts` | `PASS` |
| `HDR-04` | `FAIL`: missing header | `helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' })` | `server.ts` | `PASS` |
| `HDR-02` | `PASS` | None needed (`nosniff` already set) | n/a | `PASS` |
| `HDR-03` | `PASS` | None needed (`SAMEORIGIN` already set) | n/a | `PASS` |
| `CK-01` | `PASS`: JWT returned in JSON body and stored in `localStorage`; profile `token` cookie hardened with `HttpOnly` and `SameSite=Strict` | None needed | n/a | `PASS` |

### Known Remaining Failure

`WEB-T02` is left failing on purpose. The sink lives in the compiled Angular bundle, so a real fix means changing frontend source and recompiling. That was outside this project's scope.

---

## Additional Manual Findings (Burp Suite)

Not covered by the automated suite:

- HTTP method tampering causes an unhandled server error during checkout
- Sensitive user data and MD5 password hash exposure via `fields=password` parameter manipulation, plus JWT inspection
- SQL injection in search and login
- Email enumeration via the security question endpoint

---

## References

- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- OWASP Juice Shop source: https://github.com/juice-shop/juice-shop
- OWASP Web Security Testing Guide (WSTG): https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
