# API Security Testing

Full testing flow for REST / SOAP / GraphQL / gRPC / WebSocket APIs and token-based auth (JWT, OAuth, SAML). Payloads in [payload-reference.md](payload-reference.md); tool inventory in [tools-reference.md](tools-reference.md); shared web techniques (SQLi, SSRF, rate-limit detail) in [web-security-testing.md](web-security-testing.md); methodology/CVSS/reporting in [sdlc-security-testing.md](sdlc-security-testing.md).

The sections below are organised as OWASP API Security Top 10 maps it: the cross-cutting classes (recon, authn, authz, injection, data exposure, rate limiting) apply to every API style, then each API *type* (REST, SOAP, GraphQL, gRPC, WebSocket) has its own section for the quirks unique to it. Every design control listed is also a test: probe whether it is actually enforced, do not assume it from documentation.

---

## 1. Reconnaissance & Enumeration

Map the full attack surface before testing a single endpoint. APIs leak their own structure in more places than web apps do.

- Enumerate every endpoint across all styles (REST paths, SOAP operations, GraphQL schema, gRPC services, WebSocket channels). An endpoint you do not know about is one you cannot test.
- Discover API documentation and schema: `swagger.json`, `/api-docs`, `/openapi.json`, `/swagger-ui`, `/v2/api-docs`, `?wsdl` (SOAP), GraphQL introspection, gRPC server reflection. Exposed docs are the fastest path to a complete endpoint list.
- Enumerate versioned and environment paths: `/api/v1/`, `/api/v2/`, `/api/beta/`, `/internal/`, `/legacy/`. Older versions frequently lack controls added later.
- Identify deprecated or legacy endpoints still reachable - they are routinely forgotten by patching and WAF rules.
- Pull endpoints out of client code: mobile binaries (APK/IPA strings, decompiled source), JavaScript bundles, source maps, and historical paths in the Wayback Machine.
- Fuzz for hidden APIs at several path depths; enumerate restricted endpoints and try to reach them with path-confusion tricks (`..;/`, trailing slash, double-encoding, case changes, matrix params).
- Tools: `Postman`, `Insomnia`, `Burp Suite`, `kiterunner`, `ffuf`, `arjun`, `gau`/`waybackurls`.

---

## 2. Authentication

- Missing authentication on sensitive, internal, or admin endpoints - test each one unauthenticated before anything else.
- API keys: hardcoded in clients, leaked in JS/mobile, predictable, or never rotated. Check that old/rotated keys are actually invalidated.
- Test reuse of old, expired, or logged-out session tokens - a token that still works after logout is broken session management.
- Never accept `Basic Auth` as a primary scheme; use a standard token scheme. Do not reinvent auth, token generation, or password storage.
- Enforce `Max Retry` / lockout / jail on login, registration, OTP, and password reset; weak or missing limits enable credential stuffing and OTP brute-force.
- **JWT:** force the algorithm server-side (`HS256`/`RS256`) and never trust the token's own `alg` header (blocks `alg:none` and RS256-to-HS256 key confusion); require a long random secret (brute-force resistance); short `TTL`/`RTTL`; no sensitive data in the base64-decodable payload; keep the token small (header size limits). See the JWT attack payloads (alg:none, key confusion, weak-secret cracking, `kid` injection) in [payload-reference.md](payload-reference.md).
- **OAuth2 / OIDC:** validate `redirect_uri` server-side against an exact safelist (stops token/code theft via open redirect); use the authorization-code flow, not implicit (`response_type=token`); require a random, bound `state` value (CSRF defence); define and validate `scope` per client; check PKCE on public clients. Watch for token leakage in referrer headers, logs, and URLs.
- **SAML:** signature wrapping, comment injection in `NameID`, unsigned-assertion acceptance, and XML canonicalisation issues.

---

## 3. Authorization (BOLA, BFLA, Mass Assignment)

Broken authorization is the number-one API vulnerability class - test it on every object and every function, authenticated as a low-privilege user.

### Broken Object Level Authorization (BOLA / IDOR)
- Change object identifiers in the request and see whether you reach another user's data: `GET /api/users/123` -> `GET /api/users/124`.
- Replace your own ID with another user's in the path, body, header, or query. Target orders, invoices, documents, profiles, messages.
- **IDOR in the body or a header is often more exploitable than in the URL** (less logging, weaker checks), including nested forms like `{"id":{"id":111}}`.
- Prefer designs that avoid user-supplied resource IDs entirely: `/me/orders` over `/user/654321/orders`; use UUIDs, not auto-increment IDs (which are enumerable).

### Broken Function Level Authorization (BFLA)
- Regular user reaching admin functions: `GET /api/admin/users`, `DELETE /api/users/all`.
- HTTP method switching: an endpoint protects `GET /api/resource/1` but not `DELETE /api/resource/1`. If `GET /api/v1/users/<id>` exists, try `DELETE`/`POST` to delete or create users.

### Mass Assignment
- Send extra fields in POST/PUT/PATCH bodies to overwrite protected attributes: `role`, `isAdmin`, `verified`, `balance`, `status`. Example: `{"username":"x","isAdmin":true}`.
- Insecure `PATCH` partial updates frequently allow writing fields the UI never exposes.

### Enforcement to verify
- Every endpoint sits behind authentication (no broken auth); authorization is checked per object, not just "is logged in".
- Private APIs restricted to safelisted IPs/hosts; service-to-service calls use mTLS and validate the caller even when internal (zero-trust).

---

## 4. Input Validation & Injection
- SQL / NoSQL injection in every query param, path param, body field, and header (MongoDB operator injection `{"$gt":""}` for NoSQL).
- Command injection in fields processed server-side; SSTI in template-rendering endpoints; SSRF via any URL the server fetches.
- XXE in any endpoint accepting XML, including SOAP bodies - disable external entity parsing and entity expansion (Billion Laughs / XML bomb, and YAML anchor expansion).
- Path traversal in file download/fetch endpoints; parameter tampering on price, quantity, role, status.
- Use the correct HTTP method per operation and return `405` when inappropriate; validate the `Accept` header (content negotiation -> `406` if unsupported) and the posted `Content-Type`.
- Never put credentials, passwords, tokens, or API keys in the URL - use the `Authorization` header (URLs are logged and cached).
- Sanitize and escape all input; validate against XSS, SQLi, and RCE at the boundary. Test file-upload endpoints for type/size/extension bypass.
- **CSRF on APIs:** if the same cookie that authenticates interactive users also authorizes API calls, a crafted cross-site request can forge calls - require a custom header or token, not just the cookie.

---

## 5. Excessive Data Exposure & Output Handling
- The API returns more than the client renders - compare the raw JSON to the UI. Look for passwords (hashed or plain), tokens, PII, internal IDs, and debug fields.
- Filter bypass: omit filtering params and check whether the full dataset comes back; search responses that leak other users' records.
- Force the response `Content-Type`; set `X-Content-Type-Options: nosniff`, `X-Frame-Options: deny`, `Content-Security-Policy: default-src 'none'` on API responses.
- Remove fingerprinting headers (`X-Powered-By`, `Server`, `X-AspNet-Version`); return generic error messages and log the detail server-side only. Verbose stack traces, DB errors, and internal paths are findings.
- Use proper status codes; never return credentials, passwords, or tokens in any response body.

---

## 6. Rate Limiting & Resource Abuse
- No rate limiting on login, registration, OTP, and password reset (brute-force, enumeration, cost abuse).
- No throttling on expensive/computational endpoints; missing or bypassable pagination lets you dump the entire dataset.
- Missing request-size limits -> large-payload DoS. Example DoS via a limit param: `/api/news?limit=100` -> `/api/news?limit=9999999999`.
- GraphQL query depth/complexity DoS and batch-request abuse (1000 operations in one request) - covered per-type below.
- Rate-limit bypass tricks: IP rotation, `X-Forwarded-For` spoofing, multiple API keys, multiple accounts, case/encoding changes on the path.
- Enforcement to verify: sliding-window limits per API key *and* IP; exponential backoff on repeated auth failures; CAPTCHA/proof-of-work after suspicious activity; an API gateway applying quota, spike-arrest, and concurrent-rate policies; alerting on unusual volume/time/endpoint patterns.

---

# API-type-specific testing

Each style carries risks the generic sections above do not fully cover. Test the type-specific items in addition to sections 1-6, not instead of them.

## 7. REST
- Test every HTTP method on each endpoint: `GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD`. Auth is often enforced on one method but not another.
- HTTP parameter pollution: `?id=1&id=2` - which value wins, and does it bypass a check?
- IDOR/BOLA on all CRUD operations; insecure `PATCH` overwriting protected fields; unrestricted bulk operations.
- Content-type confusion: send `application/json` data as `text/plain` or `x-www-form-urlencoded` to dodge parsers/WAFs.
- Verbose error messages leaking stack traces, DB info, or internal paths.

## 8. SOAP
- Fetch and parse the contract: `?wsdl`, `?singleWsdl`, `disco`. The WSDL lists every operation, parameter, and type - a complete test map.
- Enumerate and invoke operations directly, including ones the client never calls; check authorization per operation.
- `SOAPAction` header: spoofing/mismatch (send operation A's body with operation B's `SOAPAction`) to bypass routing or authz.
- XML attacks in the SOAP body: XXE (external entity, SSRF via entity, file read), XML bomb / Billion Laughs, parameter/array-abuse, and XPath injection in lookups.
- **WS-Security:** test `UsernameToken` (plaintext vs digest, replay), timestamp expiry enforcement, signature verification (is an unsigned or re-signed body accepted?), and signature-wrapping attacks that move the signed element while swapping the executed one.
- Verb tampering and injection (SQLi/command) inside XML element values; verbose SOAP faults leaking server internals.
- Tools: `SoapUI`, Burp with the `Wsdler`/`SAML Raider` extensions, `wsdl2java`, custom XML in Repeater.

## 9. GraphQL
- **Introspection enabled:** `{"query":"{__schema{types{name}}}"}` - enumerate all types, queries, and mutations. If disabled, try `__type` queries and field suggestions in error messages to reconstruct the schema.
- Excessive query depth - deeply nested queries for DoS; query-complexity abuse - combine many expensive resolvers in one call.
- BOLA/IDOR via arguments: `query { user(id: 2) { email } }`; mass assignment via mutation input objects.
- **Batching and alias abuse** to bypass rate limits and brute-force: `{ a: login(...), b: login(...), c: login(...) }` sends many attempts in one HTTP request, defeating per-request limits.
- Schema and data leaks via error messages.
- Enforcement to verify: introspection off in production; depth limiting; query cost analysis; persisted/allow-listed queries where possible.
- Tools: `InQL`, `GraphQL Voyager`, `Altair`, `Burp GraphQL Raider`, `graphql-cop`.

## 10. gRPC
- Authentication on every method via call metadata (bearer tokens); test unary *and* all streaming call types - auth is sometimes only checked on unary.
- Server reflection enabled (the gRPC analogue of introspection) exposes the full service definition - enumerate with `grpcurl`.
- Message validation: malformed or oversized protobuf inputs, field-type confusion, missing-field handling.
- Replay of captured messages; TLS enforcement on the channel.
- Tools: `grpcurl`, `grpcui`, `Postman` (gRPC mode), proto files from reflection.

## 11. WebSocket
- Authentication: is the token validated on the HTTP upgrade request, or only trusted from an early message an attacker can forge?
- Message validation: inject XSS, SQLi, and command-injection payloads inside WS messages - they often skip the HTTP-layer WAF.
- Replay captured messages; test for missing nonce/sequence handling.
- **Cross-Site WebSocket Hijacking (CSWSH):** missing `Origin` check on the upgrade lets a malicious page open an authenticated socket with the victim's cookies.
- Session invalidation: does the socket keep working after the user logs out or the token expires?

---

## 12. API Versioning & Deprecated Endpoints
- Test every discovered version: `v1`, `v2`, `v3`, `beta`, `internal`, `legacy`. Older versions commonly lack auth, rate limiting, or input validation added to the current one.
- Check whether deprecated endpoints still function; look for admin/internal endpoints exposed on the public base URL.

---

## 13. Operational controls to verify

These are design controls the OWASP/shieldfy API checklist calls for; as a tester, confirm each is actually in place.

- **Transport:** HTTPS with TLS 1.2+ and secure ciphers (anti-MITM), `Host` matching SNI, `HSTS` (anti SSL-strip), directory listing off.
- **Secrets:** rotate keys/secrets on a schedule; HSM for signing; secret scanning in CI/CD; never commit secrets - env vars or a secret manager only.
- **Zero-trust:** mTLS service-to-service; validate every request even internal; short-lived auto-refreshed tokens; request signing for sensitive operations.
- **CI/CD:** unit/integration coverage of design and implementation; code review with no self-approval; dependency CVE checks (software + OS); continuous SAST/DAST; a rollback plan per deployment.
- **Monitoring:** centralized logging across services; alerting (SMS/Slack/Email/Kibana/CloudWatch); never log sensitive data (cards/passwords/PINs/tokens); IDS/IPS on API traffic.
- **Processing hygiene:** DEBUG mode off in production; CDN for file uploads; workers/queues for heavy processing to avoid HTTP blocking.

---

## 14. Quick Reference: Tools

| Category | Tools |
|----------|-------|
| API mapping | `Burp Suite`, `Postman`, `Insomnia`, `kiterunner` |
| Fuzzing | `ffuf`, `arjun`, `api-fuzzers` |
| REST | `Burp`, `Postman`, `ffuf` |
| SOAP | `SoapUI`, Burp `Wsdler`, `SAML Raider`, `wsdl2java` |
| GraphQL | `InQL`, `GraphQL Voyager`, `Altair`, `Burp GraphQL Raider`, `graphql-cop` |
| gRPC | `grpcurl`, `grpcui` |
| Auth | `jwt_tool`, `oauth2-proxy`, `SAML Raider`, `Burp` |
| Docs discovery | `ffuf` (swagger wordlist), `kiterunner` |
| General | `OWASP ZAP`, `mitmproxy` |

(Full inventory in [tools-reference.md](tools-reference.md).)

---

## 15. Wordlists & references
- `chrislockard/api_wordlist`, SecLists `common-api-endpoints`, SecLists `Discovery/Web-Content/api`, fuzzdb `common-methods`.
- OWASP API Security Top 10; HackTricks Web-API pentesting; `shieldfy/API-Security-Checklist`; `yosriady/api-development-tools`.
