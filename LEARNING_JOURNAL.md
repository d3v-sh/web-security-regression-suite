# Learning Journal

Notes from building `web-security-regression-suite` against an isolated local OWASP Juice Shop (`http://localhost:3000`, synthetic accounts only). See [`README.md`](README.md) for scope, setup, and results (**3 passed, 6 failed → 8 passed, 1 failed**).

---

## Part 1: Core Concepts

### 1. Server-side input validation vs. SQLite column assumptions (`WEB-T01`)

`POST /profile` accepted a 500-char `username` and responded `HTTP 302` (normal success redirect). The database did not stop it either.

- **SQLite does not enforce declared lengths.** A column typed `VARCHAR(50)` is only a hint (type affinity). SQLite stores longer strings without error. Relying on the schema as a length limit is a false assumption.
- **The ORM does not validate by default.** Sequelize models only enforce what is declared in validators; absent those, input flows straight to the query.
- **Validation belongs in the handler**, before any data access. The fix in `routes/updateUserProfile.ts` checks type (must be a string) and length (1–50) before `UserModel.findByPk(...)` and returns `HTTP 400 Bad Request`.
- Client-side `maxlength` attributes are UX, not security. Any HTTP client can bypass them.

**Takeaway:** validate type, length, and format at the trust boundary, and fail with a clean 4xx, not a stack trace.

### 2. SPA DOM sinks vs. REST JSON serialization (`WEB-T02`)

Reflected/DOM XSS in a single-page app and injection in a REST API are different problems in different layers.

- A REST endpoint such as `/rest/products/search` returns JSON. The payload `<tag>test</tag>` appears in that JSON as an inert string. JSON serialization does not execute anything.
- The danger appears when the **frontend renders** that string. Angular sanitizes interpolated HTML by default. `DomSanitizer.bypassSecurityTrustHtml()` explicitly **turns that protection off** for the value passed in. That call is the sink.
- Output encoding is the responsibility of the rendering context (HTML, attribute, JS, URL), not the API that stores or returns the data.
- Testing the API response for the sink is therefore the wrong layer. The evidence is in the compiled frontend bundle (`/main.js`) and in the browser behaviour (manually confirmed via `<tag>test</tag>` in the search bar).

**Takeaway:** find the sink where the data is rendered, not where it is transported.

### 3. Client-side route guards vs. backend RBAC (`WEB-T03`)

`/#/administration` was protected only by an Angular route guard. The API behind it was not.

- A route guard controls which **screen** the browser shows. It runs in the user's browser, so the user controls it.
- An attacker skips the UI and calls `GET /api/Users` directly with any valid low-privilege JWT. Result before the fix: `HTTP 200`, 13976 bytes of user records.
- Authorization must be enforced on the server for every request. The fix in `server.ts` adds `user.data.role !== 'admin'` inside the `autoModels` loop before `finale.resource` mounts `/api/Users` and `/api/Users/:id`. After: `HTTP 403`, 50 bytes.
- Care point: `POST /api/Users` stays public because registration depends on it. Blanket-protecting the resource would have broken sign-up, which is why the check is applied per route.

**Takeaway:** the UI hiding something is not access control. Test the API with a low-privilege token.

### 4. HTTP security headers (`HDR-01` to `HDR-04`)

Headers instruct the browser to apply defensive behaviour.

| Header | Purpose |
|--------|---------|
| `Content-Security-Policy` | Restricts script/style/frame sources. Limits XSS impact. |
| `Referrer-Policy: strict-origin-when-cross-origin` | Limits URL data leaked to other origins via `Referer`. |
| `X-Content-Type-Options: nosniff` | Stops MIME-type sniffing. |
| `X-Frame-Options: SAMEORIGIN` | Blocks framing by other origins (clickjacking). |

- `HDR-02` and `HDR-03` already passed. `HDR-01` and `HDR-04` failed until `helmet.contentSecurityPolicy(...)` and `helmet.referrerPolicy(...)` were configured in `server.ts`.
- **A presence check is a floor, not a grade.** The suite confirms the header exists. A permissive CSP (for example `unsafe-inline`) still passes the check while giving weak protection. Policy quality needs separate review.
- Headers are defence in depth. They reduce impact; they do not fix `WEB-T02`.

### 5. Session storage and cookie flag trade-offs (`CK-01`)

Where the session token lives decides which attacks matter.

| Storage | Readable by JS (XSS can steal it) | Sent automatically (CSRF risk) |
|---------|-----------------------------------|--------------------------------|
| `localStorage` | Yes | No (must be attached manually) |
| Cookie with `HttpOnly` | No | Yes, unless `SameSite` restricts it |

- Juice Shop returns the JWT in the JSON body of `POST /rest/user/login` and the frontend keeps it in `localStorage`. Any XSS (including the unpatched `WEB-T02` sink) can read it.
- The profile `token` cookie is hardened with `HttpOnly` (blocks JS access) and `SameSite=Strict` (blocks cross-site sends). `CK-01` passes on this basis.
- Neither choice is free. `HttpOnly` cookies remove token theft via XSS but bring CSRF concerns that `SameSite` or CSRF tokens must cover. `localStorage` avoids CSRF but concentrates risk on XSS.

---

## Part 2: Troubleshooting Walkthroughs

### Diagnosis 1: `WEB-T01` false `HTTP 500` stack trace

**Symptom.** The first version of the Go check sent the oversized `username` to `POST /profile` and received `HTTP 500` with a stack trace. That looked like a vulnerability finding ("input crashes the server"), but the result did not match what the browser did with the same payload.

**Root cause.** The Go client authenticated with `Authorization: Bearer <jwt>`. The handler in `routes/updateUserProfile.ts` does not read that header; it reads `req.cookies.token`. With no cookie, the handler ran with no authenticated user and threw. The 500 reflected a **wrong authentication transport in my test**, not the length bug I was trying to measure.

**How it was diagnosed.**
1. Replayed the same action in the browser with Burp Suite capturing the traffic. The request that worked carried `Cookie: token=<jwt>`, not an `Authorization` header.
2. Diffed the Burp capture against the request the Go program actually sent (headers, body encoding, content type). The only material difference was the auth mechanism.
3. Read `routes/updateUserProfile.ts` to confirm: it pulls the token from `req.cookies.token`.

**What changed.**
- `regression_suite.go`: send `Cookie: token=<jwt>` for this request, and treat `302` with the oversized payload accepted as the true "before" result (`FAIL`).
- `routes/updateUserProfile.ts`: added server-side type and length (1–50) validation before `UserModel.findByPk(...)`, returning `HTTP 400`.
- Check now asserts `accepted=false` and `stack_trace=false`. Final result: `PASS` (`HTTP 400`).

**Lesson.** When a result is surprising, replay the request in a proxy and compare byte-for-byte against the test client before blaming the target. Also assert on stack-trace absence explicitly; a 4xx alone does not prove errors are handled cleanly.

---

### Diagnosis 2: `WEB-T02` false-positive `PASS`

**Symptom.** The first implementation of `WEB-T02` reported `PASS`, yet manually entering `<tag>test</tag>` in the search bar showed the application rendering the input as HTML.

**Root cause.** The check inspected the JSON from `/rest/products/search`. That response only contains the data as a string, so nothing in it looks like a sink. The vulnerability is in the **frontend**: Angular's `DomSanitizer.bypassSecurityTrustHtml()` disables sanitization at render time. Checking the transport layer could never detect it.

**How it was diagnosed.**
1. Compared the automated result (`PASS`) with the manual behaviour (HTML injection visible in the UI). Contradiction → the check measured the wrong thing.
2. Traced the data flow: the search term is rendered by the Angular app, so the relevant code is in the compiled bundle.
3. Looked in `/main.js` and located `bypassSecurityTrustHtml`.

**What changed.**
- `regression_suite.go`: `WEB-T02` now fetches `/main.js` and searches for the `bypassSecurityTrustHtml` sink. Result: `FAIL` (`HTTP 200`, `bypassSecurityTrustHtml_sink=true`), matching manual evidence.

**Lesson.** A passing test that contradicts manual evidence is a bug in the test. Detect a vulnerability at the layer where it exists.

---

## Part 3: Remaining Limitations

**`WEB-T02` is not fixed (final result: 8 passed, 1 failed).**
- Removing the sink requires editing the Angular source and recompiling the frontend with `ng build`. I treated that as an intentional scope boundary and left it failing rather than hiding it.
- The check is a string match for the sink in `/main.js`. It proves the dangerous API is present, not that every use is exploitable. It can also break if the bundle is minified or renamed differently. Manual confirmation remains necessary.

**`localStorage` JWT trade-offs.**
- The login flow returns the JWT in the JSON body and the frontend stores it in `localStorage`. Any script running on the origin can read it, so the unpatched `WEB-T02` sink and this storage choice compound each other.
- `CK-01` passes because the cookie flags it checks are present (`HttpOnly`, `SameSite=Strict` on the profile cookie). That is a narrower result than "sessions are safe".
- A proper fix is an architecture change (move the session token to an `HttpOnly` cookie, add CSRF handling), not a one-line patch.

**Other gaps.**
- Header checks confirm presence, not policy strength (see concept 4).
- Findings from manual Burp Suite testing are not automated: HTTP method tampering error at checkout, MD5 password hash exposure via `fields=password` manipulation, SQL injection in search/login, and email enumeration via the security question endpoint. They are candidates for future regression cases.
