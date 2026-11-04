# API Security - Reference & Interview Prep

REST, SOAP and GraphQL, plus token-based authentication (JWT, OAuth). Vulnerabilities follow the same **What -> Why -> How -> Impact -> Mitigations** shape used in [web-security.md](web-security.md); session/cookie/auth basics and the full rate-limit/SSRF detail live there.

---

## 1. Fundamentals

### Why API security is treated as a distinct discipline
APIs are consumed by arbitrary clients - mobile apps, other services, scripts - with no browser enforcing the Same-Origin Policy, CSP or cookie rules. There is no client-side safety net, so authorization has to be enforced server-side on every single request, which is exactly the check teams most often forget. That is why Broken Object Level Authorization is the number-one API risk.

### How API testing differs from web app testing
There is usually no rendered UI to walk, so you work from captured traffic, an OpenAPI/Swagger spec, or a Postman collection. The emphasis shifts away from output-rendering bugs (like reflected XSS) toward object- and function-level authorization, token handling, mass assignment, excessive data exposure, and resource consumption.

### OWASP API Security Top 10 (2023)
1. **BOLA** - Broken Object Level Authorization (the API form of IDOR).
2. **Broken Authentication** - weak JWT validation, missing/short token expiry, credential stuffing, leaked keys.
3. **Broken Object Property Level Authorization** - excessive data exposure plus mass assignment.
4. **Unrestricted Resource Consumption** - no rate/size/complexity limits (DoS, cost abuse).
5. **BFLA** - Broken Function Level Authorization.
6. **Unrestricted Access to Sensitive Business Flows** - automated abuse of a legitimate flow (bulk buying, mass sign-ups).
7. **SSRF**.
8. **Security Misconfiguration**.
9. **Improper Inventory Management** - old/undocumented/shadow versions still live.
10. **Unsafe Consumption of APIs** - blindly trusting third-party/partner API data.

### How do you test an API with no documentation?
Capture traffic from the web or mobile client; hunt for spec files (`/swagger.json`, `/api-docs`, `/v2/api-docs`); read JS bundles for endpoints; fuzz paths with ffuf; try older versions (`/v1/` when the app uses `/v2/`); change HTTP methods (GET -> PUT/DELETE); and discover parameters with Arjun.

---

## 2. Authorization

### Broken Object Level Authorization (BOLA / API-IDOR)
**What it is.** An endpoint returns or modifies an object identified by an ID without verifying the caller owns it.

**Why it happens.** Authentication passes (the token is valid) but authorization - "does this user own *this* object" - is never separately checked.

**How you test it.** Authenticated as user A, request your own object (`GET /api/orders/1001`), then change the ID (`/orders/1002`) and see if another user's data returns. It applies to UUIDs too (not enumerable, still unchecked) and to nested child objects where only the parent is checked.

**Impact.** Reading or modifying other users' data; mass exposure when IDs are enumerable.

**Mitigations.** Scope every object fetch at the query level (`WHERE id=? AND customer_id=?`); return identical 404s whether the object is missing or simply not yours; and add automated tests asserting A cannot fetch B's known ID.

### Broken Function Level Authorization (BFLA)
**What it is.** A user can call a function/endpoint their role should not permit - the authorization gap is about the *action*, not the object.

**Why it happens.** The endpoint checks only that a valid token exists, never that the token's role is allowed to perform this action.

**How you test it.** Call admin or privileged endpoints (found in docs or JS) with a normal user's token, e.g. `POST /api/admin/users/{id}/promote`, and see if it succeeds.

**Impact.** Vertical escalation to admin functionality; horizontal abuse of another role's functions.

**Mitigations.** Enumerate every endpoint by intended role and enforce role checks server-side on each; explicitly test every "restricted" endpoint with a lower-privileged and an unauthenticated token.

### Broken Object Property Level Authorization: Mass Assignment & Excessive Data Exposure
**What it is.** Two sides of the same problem. **Mass assignment** is the server binding the whole client JSON body to an internal model, so a client can set fields it shouldn't. **Excessive data exposure** is the API returning full objects (including sensitive fields) and relying on the frontend to hide them.

**Why it happens.** Convenient framework auto-binding (`Model.update(req.body)`) writes any field present on the model, and default serializers return the whole model rather than a tailored view.

**How you test it.** For mass assignment, add fields the UI never exposes to a request body - `"role":"admin"`, `"isVerified":true`, `"balance":99999`, `"account_tier":"enterprise"` - and check whether they persist. For excessive exposure, read raw responses in Burp (not the UI) looking for password hashes, other users' emails, or internal flags.

**Impact.** Privilege escalation, data tampering, and sensitive-data disclosure.

**Mitigations.** Use an explicit allow-list of client-writable fields per endpoint (DTOs), never bind the raw request body; in Laravel use `$fillable`, not `$guarded = []`; put privileged fields behind their own authorized endpoint; and return only the fields each client needs via response DTOs.

### Gateway vs service-level responsibilities
A gateway should handle coarse cross-cutting controls - TLS termination, authentication, global rate limiting, schema validation - while each service still enforces fine-grained, resource-level (BOLA-style) authorization. Assuming "the gateway already did auth" and skipping in-service ownership checks is the single most common path to BOLA.

---

## 3. JSON Web Tokens (JWT)

**What it is.** A JWT is a compact, URL-safe token for transmitting signed claims as a JSON object, widely used for authentication and authorization. It has three dot-separated parts: a **header** (metadata such as `{"alg":"HS256","typ":"JWT"}`), a **payload** (claims such as `{"userId":123,"role":"admin","exp":...}`), and a **signature** (e.g. `HMACSHA256(base64url(header) + "." + base64url(payload), secret)`). In a typical flow the user logs in, the server issues a JWT, the client stores it (localStorage, sessionStorage or a cookie) and sends it as `Authorization: Bearer <token>`, and the server verifies the signature on each request.

**Why it becomes vulnerable.** JWTs are not insecure by design - bad implementation makes them so: allowing `alg:none` or mixing HS256/RS256 (signature bypass), weak signing secrets (brute-forceable), no expiry or revocation (a leaked token stays valid), storing tokens in localStorage (XSS theft) or in cookies without `SameSite`/`HttpOnly` (CSRF), unvalidated claims (tampered `role`/`admin`), and skipping signature verification entirely (any token accepted). Remember the payload is only base64-encoded, not encrypted, so anyone can read it.

**How you test and exploit it.** Decode the token (jwt.io, `jwt_tool`) and read the claims, then try the known attacks:
- **None-algorithm attack** - set `alg:none` and strip the signature; if accepted, forge any token.
- **Algorithm confusion (RS256 -> HS256)** - if the server accepts both and uses the RSA public key as the HMAC secret, sign a forged token with that public key.
- **Key injection / key confusion** - supply your own key via a `jwk`/`jku`/`x5u` header and see if the server verifies against it; `kid` injection via path traversal or SQLi in the key ID.
- **Weak-secret brute force** - crack an HS256 secret with hashcat/`jwt_tool` and re-sign.
- **Expired-token replay / token replay** - reuse a previously valid token, or replay the same token across endpoints, where expiry/replay are not enforced.
- **XSS token theft** - steal a JWT from localStorage/sessionStorage via XSS.
- **Improper revocation** - confirm old tokens still work after logout or access removal.
- **Refresh-token replay** - use a stolen refresh token (not bound to session/IP) to mint new access tokens.
- **Claim injection/tampering** - tamper `sub`/`iss`/`aud`/`role` if claims aren't validated server-side, to impersonate or escalate.

**Impact.** Authentication bypass, impersonation, privilege escalation, and persistent access via un-revocable tokens.

**Mitigations.** Pin one expected algorithm server-side (never trust the token's `alg`); use strong secrets or properly separated asymmetric keys; enforce short expiry with a revocable refresh-token pattern (and a blacklist/denylist where revocation is required); validate all claims (`sub`, `iss`, `aud`, `exp`) server-side; keep sensitive data out of the payload; and prefer `HttpOnly`+`Secure`+`SameSite` cookies over localStorage for browser clients.

### Where should a JWT be stored client-side?
`HttpOnly`+`Secure`+`SameSite` cookies are safest against XSS theft (script can't read them) but reintroduce CSRF, so pair them with CSRF tokens. localStorage/sessionStorage is readable by any XSS on the origin - one stored XSS equals full token theft - so only use it with heavy XSS controls (CSP, output encoding).

---

## 4. OAuth 2.0

**What it is.** OAuth is an open standard for **access delegation** - it lets a user authorize a third-party app to access their data on another service (Google, Facebook, GitHub) without sharing their password. It is what sits behind "Login with Google". The key roles are the **resource owner** (the user), the **client** (the requesting app), the **authorization server** (authenticates the user and issues tokens), the **resource server** (hosts the data), and the **access token** (the temporary credential).

**How the flow works (Authorization Code grant).** The client redirects the user to the authorization server to log in; the user authenticates and grants permission; the authorization server redirects back with an authorization **code**; the client exchanges that code for an **access token** at the token endpoint; the client then uses the token to call the resource server.

**Why it becomes vulnerable, and how you test it.**
- **Misconfigured redirect URIs** - loose matching or wildcards let an attacker redirect the code/token to a site they control (chain with open redirect -> token leak).
- **CSRF in the OAuth flow** - if the client doesn't validate the `state` parameter, an attacker can force the victim to authorize the attacker's context.
- **Token leakage via Referrer** - tokens placed in the URL leak through `Referer` headers and logs.
- **Authorization-code interception** - over an insecure channel, or on mobile where a malicious app registers the same custom URI scheme, the code can be stolen.
- **Client impersonation** - a leaked client secret lets an attacker impersonate the client.
- **Implicit flow** - deprecated for SPAs because the token is exposed directly in the URL.

**Impact.** Account takeover via stolen codes/tokens, unauthorized access to delegated resources, and scope escalation.

**Mitigations.** Use **PKCE** for public/mobile/SPA clients; pre-register and strictly validate exact **redirect URIs** (no wildcards/open redirects); use and verify the **`state`** parameter to stop CSRF; enforce **HTTPS** throughout; never put tokens in the URL and avoid the implicit flow; issue **short-lived access tokens** with refresh tokens; and apply least-privilege **scopes**.

### OAuth2 vs OpenID Connect (OIDC)
OAuth2 handles authorization (delegated access, issues access tokens). OIDC is an identity layer on top that also issues an ID token (a JWT proving *who* the user is). "Login with Google" is really OIDC. Never treat a bare OAuth2 access token as proof of identity.

### Why PKCE is needed for public clients
Public clients can't keep a secret, so a malicious app registering the same redirect URI could intercept the authorization code and exchange it. PKCE binds the code to a `code_verifier` only the legitimate client holds, so an intercepted code is useless without it.

### SAML SSO vulnerabilities
**What it is.** SAML (Security Assertion Markup Language) is an XML-based single-sign-on standard: an Identity Provider (IdP) issues a digitally signed *assertion* vouching for the user to a Service Provider (SP). Where OAuth/OIDC pass signed tokens, SAML passes signed XML - and almost all of its vulnerabilities come from mishandling that signed XML.

**Why it becomes vulnerable.** The SP must verify an XML signature over XML the attacker can see and manipulate, and XML's flexibility (comments, canonicalisation quirks, multiple same-named elements) makes correct signature validation hard to implement.

**How you test and exploit it.**
- **XML Signature Wrapping (XSW)** - add a second, unsigned assertion (or relocate the signed one) so the SP validates the signature against the original element but reads identity from the attacker-injected element: change the user to `admin` while keeping a technically valid signature. Burp's **SAML Raider** automates the XSW permutations.
- **Assertion injection / unsigned assertions** - if the SP accepts assertions with a missing signature, or signs only part of the document, inject or edit claims such as `NameID` and role attributes.
- **Signature stripping / algorithm downgrade** - remove the signature element, or force a weak/`none` algorithm, if the SP doesn't strictly enforce one.
- **Comment injection in `NameID`** - e.g. `admin@x.com<!---->.evil.com` to exploit parser/canonicalisation differences and impersonate another user.
- **Missing condition checks** - `Recipient`, `Audience`, `InResponseTo` and `NotOnOrAfter` not validated enable assertion replay and cross-SP reuse.

**Impact.** Full authentication bypass and impersonation of any user, including administrators.

**Mitigations.** Validate the signature over the whole assertion with a vetted library, reject unsigned or partially-signed assertions, pin the expected IdP certificate, enforce `Recipient`/`Audience`/`InResponseTo`/`NotOnOrAfter`, and never hand-roll XML/signature handling. For new applications, prefer OIDC over SAML.

---

## 5. GraphQL

**What it is.** GraphQL (from Facebook) is a query language and runtime for APIs. The client asks for exactly the fields it wants from a single endpoint (typically `/graphql`), against a strongly typed schema, with hierarchical/nested queries - so there is no over- or under-fetching and multiple resources can be retrieved in one request. For example a query for `user(id:"123"){ name email posts{ title published } }` returns just those fields as JSON. The benefits over REST are precise fetching, fewer round-trips, and a typed schema that tools can auto-document.

**Why it becomes vulnerable.** The client composes arbitrary nested traversals of the data graph, so if authorization or cost limits are enforced only at the query root (not in each field resolver), deeper or aliased fields go unchecked; schema introspection can leak the entire API; and batching lets one request contain many operations.

**How you test and exploit it.**
- Find the endpoint (`/graphql`, `/graphiql`, `/api/graphql`).
- **Introspection** - `{__schema{types{name fields{name}}}}` dumps the schema; if disabled, rebuild it from field suggestions (Clairvoyance).
- **IDOR** via queries using other users' IDs, and **mutations** that lack authorization.
- **Batching / aliasing** - send many operations (or alias the same sensitive field many times) in one request to brute-force OTPs/logins past rate limits or bulk-extract data past a root-only auth check.
- **Deep nested queries** for denial of service.
- **Injection** inside arguments.
- Tools: InQL (Burp), GraphQL Voyager, graphw00f.

**Impact.** Schema/data disclosure, authorization bypass, rate-limit bypass, and resource-exhaustion DoS.

**Mitigations.** Enforce a maximum query depth and a computed cost/complexity budget at the validation layer; disable introspection and batching in production; and enforce authorization inside every field resolver, not just at the query root.

### A GraphQL attack with no REST equivalent
Field aliasing/batching to defeat a root-level-only authorization or rate-limit check, and nested-query resource exhaustion from a single small-looking request - both come from the client being able to compose arbitrary nested graph traversals.

---

## 6. SOAP

**What it is.** SOAP (Simple Object Access Protocol) is a strict, XML-based messaging protocol for web services, still common in enterprise, banking, telecom and legacy systems. Every message is an XML **envelope** (header + body), the service is described by a **WSDL** contract that lists all operations/parameters/types, and security is often layered on with **WS-Security** (signatures, encryption, `UsernameToken`). Unlike REST's lightweight JSON over HTTP verbs, SOAP is transport-agnostic, rigidly typed, and verbose - which makes the WSDL a complete map of the attack surface and the XML parser a rich source of bugs.

**Why it becomes vulnerable.** It is XML end-to-end, so every XML weakness applies (external entities, entity expansion, signature-wrapping); the WSDL exposes every operation including ones the client never calls; routing by the `SOAPAction` header can be desynchronised from the body; and WS-Security is hard to implement correctly (unsigned elements accepted, timestamps not enforced, signatures not covering the whole body).

**How you test and exploit it.**
- **Get the contract:** `?wsdl`, `?singleWsdl`; load in Burp (**Wsdler**), SoapUI or Postman to enumerate and invoke every operation - then check authorization per operation, including ones the UI never triggers.
- **XXE** in the SOAP body - external entity to read files or SSRF internal services; **XML bomb / Billion Laughs** for DoS.
- **SOAPAction spoofing** - send operation A's body with operation B's `SOAPAction` header to bypass routing or authorization checks keyed on one but not the other.
- **WS-Security attacks** - `UsernameToken` replay or plaintext/digest weaknesses; timestamp-expiry not enforced (replay); **XML Signature Wrapping** (move the signed element while swapping the executed one, as in SAML XSW); accepting an unsigned or re-signed body.
- **Injection inside XML fields** - SQLi, command injection, and XPath injection in element values; verbose SOAP **faults** leaking stack traces and internals.

**Impact.** File read/SSRF (XXE), authentication/authorization bypass (SOAPAction, signature wrapping), DoS (XML bomb), and data disclosure via faults.

**Mitigations.** Disable external entity and DTD processing in the XML parser; validate against the schema; enforce authorization per operation (not per endpoint); require WS-Security signatures over the whole body with timestamp/nonce replay protection; and return generic SOAP faults. Tools: `SoapUI`, Burp `Wsdler` + `SAML Raider`, `wsdl2java`.

---

## 7. Resource consumption, inventory & third parties

### Rate limiting
Rate limiting caps how many requests an identity can make in a window; its absence enables brute force, credential stuffing and DoS. API limits must be per-identity (token/key), tiered by endpoint cost, and capped on payload/result size - not just per-IP. The full testing-and-bypass detail (scope, header spoofing, IP rotation, parallel-burst races, alternate endpoints) is in [web-security.md](web-security.md#rate-limiting-and-bypass).

### Improper inventory management (shadow APIs)
**What it is.** Undocumented, deprecated or forgotten endpoints still live and unprotected - old app-version endpoints, debug endpoints shipped by accident, one-off integrations.

**How you test it.** Enumerate via JS bundles, the Wayback Machine, and `/api/v1/` fuzzing; a decompiled mobile app often reveals routes like `/v2/debug/dump-user-session`.

**Mitigations.** Route all traffic through one gateway with default-deny for unregistered routes, strip debug endpoints at build time, and run continuous API discovery against the documented inventory.

### Unsafe consumption of third-party APIs
**What it is.** Trusting upstream/partner responses without the validation applied to user input - e.g. a forged payment-processor webhook with no signature check credits an order as paid.

**Mitigations.** Treat every third-party response as untrusted: verify webhook signatures (HMAC), validate schemas, and don't blindly follow redirects from partner responses.

### SSRF via a webhook/import feature
A "fetch this URL" field reaches internal targets; DNS rebinding can pass a naive hostname check before the fetch hits `169.254.169.254` or an internal service. Resolve DNS and validate the actual IP against blocked ranges immediately before each fetch, including on every redirect hop. Full SSRF detail is in [web-security.md](web-security.md#server-side-request-forgery-ssrf).

### Token replay and API keys
Protect against **token replay** with short lifetimes, strict `aud` validation, one-time nonces/tracked IDs, and TLS everywhere. For **API keys and secrets**, look in JS files, mobile app resources (`strings.xml`, decompiled code), public GitHub, error messages and the Wayback Machine, then check what the key unlocks and whether it is properly scoped.
