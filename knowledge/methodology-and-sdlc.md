# VAPT Methodology, Reporting & Secure SDLC - Interview Q&A

Engagement lifecycle, risk rating, reporting, standards, threat modeling, and secure-development topics.

> Secure-development companions (phases of this lifecycle): design -> [application-architecture-review.md](application-architecture-review.md); implementation -> [source-code-audit.md](source-code-audit.md).

---

## 1. VAPT methodology & engagement

### Vulnerability Assessment vs Penetration Test?
VA identifies and catalogs weaknesses (mostly automated, breadth-first). PT actively exploits them to prove real-world impact and finds logic/chained flaws scanners miss (mostly manual, depth-first). VAPT combines both - run VA continuously, PT periodically or after major changes.

### Black-box vs grey-box vs white-box?
Black = no internal knowledge (external-attacker view). Grey = partial access, e.g. test accounts or API docs (most common in client work, best ROI - mirrors a compromised insider). White = full access including source. Note the time/cost trade-off: black-box finds fewer bugs per hour.

### Walk through your standard VAPT methodology.
Scoping & rules of engagement -> passive/active recon -> automated scanning -> manual verification & exploitation -> post-exploitation/impact proof (within scope) -> reporting -> remediation support -> retest. Capture evidence at every phase - in consulting, an unreported finding didn't happen.

### What do you confirm in a scoping call?
Assets (URLs, APIs, apps, versions), environment, roles & test accounts, black/grey box, testing window and blackout dates, out-of-scope items, whether production is in scope, points of contact + emergency contact, reporting format and retest terms. Get written authorisation before testing.

### How do you test production safely?
Prefer staging; if production-only, time-box to low-traffic windows, avoid destructive payloads (`OR 1=1` on UPDATE/DELETE, mass account lockouts), rate-limit your own scanning, use test accounts, and agree a stop-testing signal and contact up front.

### How do you handle scanner false positives?
Manually reproduce each one, cross-reference a second tool, and check version/patch context before it reaches a report. Never ship an unverified automated finding into a client deliverable.

### What is your retesting process beyond "does the PoC still work"?
Confirm (a) the original PoC fails, (b) logically similar bypass variants also fail (developers often patch only the literal case), (c) the fix didn't break functionality or introduce a new issue.

### How do you plan a large app with limited time (e.g. 5 days, 3 roles, 200 endpoints)?
Day 1: client walkthrough, set up accounts, map the app, kick off background scans. Days 2-4: prioritise high-risk areas first (auth, payments, admin, file upload, data export), test access control across all roles, then injection and logic. Day 5: validate, report, and surface critical issues immediately. Tell the client up front what will be deep vs light.

### You find a critical issue on day 1 of a two-week engagement. What do you do?
Validate it, gather evidence, notify the client contact and your lead right away (don't wait for the final report), suggest an interim mitigation, log it in the tracker, and keep testing the rest.

### You accidentally cause downtime/data change in production. What do you do?
Stop testing that area, immediately inform the client contact and your manager with exactly what was sent and when, help them recover, and document it. Prevent by confirming windows and avoiding destructive payloads.

### How do you stay updated?
PortSwigger research & Web Security Academy labs, HackerOne Hacktivity disclosed reports, CVE feeds/NVD, security researchers on X, OWASP projects. Name two concrete recent things you read.

---

## 2. Risk rating & CVSS

### Explain CVSS v3.1 base metrics.
- **AV** Attack Vector: Network / Adjacent / Local / Physical
- **AC** Attack Complexity: Low / High
- **PR** Privileges Required: None / Low / High
- **UI** User Interaction: None / Required
- **S** Scope: Unchanged / Changed (impact crosses a security boundary, e.g. stored XSS hitting other users)
- **C/I/A** Confidentiality / Integrity / Availability: None / Low / High
- Bands: 0.0 None | 0.1-3.9 Low | 4.0-6.9 Medium | 7.0-8.9 High | 9.0-10.0 Critical.

Worked vectors:

| Finding | Vector | Score |
|---|---|---|
| Unauthenticated SQLi, full DB access | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 Critical |
| CSRF changing email (ATO path) | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | ~8.0 High |
| IDOR reading other users' PII (logged-in) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 Medium |
| Reflected XSS needing a click | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | ~6.1 Medium |
| Stored XSS by a user, viewed by others | `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | ~5.4 Medium |

In a live exercise, **narrate each metric and why** - the reasoning scores higher than the exact decimal.

### CVSS says Medium but you think it's critical for the client. What do you do?
CVSS base measures technical severity, not business risk. Report the honest CVSS vector, then state business impact separately (e.g. an IDOR exposing all customers' KYC in a fintech), and give a final risk rating combining both. CVSS 4.0 adds threat/environmental metrics for exactly this.

---

## 3. Reporting & tracking

### What goes into a VAPT report?
1. Executive summary (non-technical). 2. Scope, window, approach, tools, limitations. 3. Findings summary table with severity counts. 4. Each finding: title, severity + CVSS vector, affected endpoint/parameter, description, steps to reproduce, PoC request/response + screenshots, business impact, recommendation, references (OWASP/CWE). 5. Retest status.

### What's in an executive summary?
One page for management: overall risk posture in a line, counts of Critical/High/Medium/Low, the top 3 risks in business language ("any customer could view other customers' loan details"), and the priority actions. No payloads or jargon.

### How do you write a report useful to both a developer and a CISO?
Two tiers: a business-risk executive summary for leadership, and detailed technical findings with PoCs, CVSS, and specific remediation (code patterns/config changes, not just "fix the vulnerability") for developers.

### How do you manage a vulnerability tracker?
One row per finding: ID, title, asset, severity + CVSS, status (Open / In progress / Fixed / Retest pending / Closed / Risk accepted), client-side owner, date found, target fix date by SLA (e.g. Critical 7 days, High 15-30), retest date and evidence. Share weekly, chase overdue items, close only after a retest proves the fix.

### A client/developer disputes a finding or its severity. What do you do?
Re-test it, share the exact request/response plus video/screenshots, and walk them through the CVSS metrics and impact on a call. If they prove a compensating control, re-rate and note it. Stay factual, never defensive; escalate via the PM if unresolved and document the decision.

---

## 4. Standards & frameworks

### Which testing standards do you align to?
OWASP WSTG / ASVS (web depth & coverage), OWASP API & MASVS (API/mobile), PTES (full engagement lifecycle), NIST SP 800-115 (technical testing guide), OSSTMM. Client reports often map findings to a recognised standard for compliance (PCI-DSS, SOC 2, ISO 27001).

### What is PTES?
Penetration Testing Execution Standard - seven phases: pre-engagement interactions, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, reporting.

### Which NIST documents matter here?
SP 800-115 (technical security testing), CSF 2.0 (six functions: Govern, Identify, Protect, Detect, Respond, Recover), SP 800-53 (security control catalogue).

### CIS Controls vs CIS Benchmarks?
CIS Controls v8 = 18 prioritised security controls (asset inventory, secure config, vuln management...). CIS Benchmarks = hardening guides for specific systems (Linux, Windows, AWS, databases), used in configuration reviews.

### What does PCI DSS require for testing?
v4.0 Req 11: internal and external vulnerability scans at least quarterly (external by an ASV) and penetration testing at least annually and after significant changes, covering app and network layers plus segmentation testing. Req 6 covers secure development and protecting public-facing web apps.

### OWASP Top 10 - current web list (2025)?
A01 Broken Access Control (now folds in SSRF), A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection (XSS folded in), A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions. (If the panel works from the 2021 list, say you're fluent in both and note what moved.)

---

## 5. Threat modeling

### What is threat modeling and how do you do it?
Identifying what can go wrong in a design before/alongside testing: draw a data-flow diagram with trust boundaries, enumerate threats per component (commonly with STRIDE), rate them, and decide mitigations.

### STRIDE?
| Threat | Violates | Example |
|---|---|---|
| Spoofing | Authentication | Stolen session token |
| Tampering | Integrity | Changing a loan amount in a request |
| Repudiation | Non-repudiation | No audit log of admin actions |
| Information disclosure | Confidentiality | IDOR exposing KYC data |
| Denial of service | Availability | No rate limit on an OTP endpoint |
| Elevation of privilege | Authorization | User calls an admin API |

### DREAD and MITRE ATT&CK vs STRIDE?
STRIDE *identifies* threat categories (design phase). DREAD *scores/prioritises* them (Damage, Reproducibility, Exploitability, Affected users, Discoverability) - though many orgs now prefer CVSS-style scoring as DREAD is subjective. MITRE ATT&CK is a knowledge base of real attacker TTPs, used to sanity-check controls against real-world behaviour (detection/red-team context).

### Threat-model a loan application flow.
Assets: borrower PII, KYC docs, loan amounts, bank details. Entry points: signup, OTP, KYC upload, loan form, admin approval, partner APIs. Key threats: OTP brute force (DoS/spoofing), IDOR on KYC docs (disclosure), amount tampering after approval (tampering), malicious file upload (elevation), missing audit trail on approvals (repudiation). Mitigations: rate limiting, object-level checks, server-side recalculation/signing of approved values, file validation + isolated storage, audit logging.

### How do you fit threat modeling into Agile?
Threat-model only the *delta* of new features/significant changes as part of story refinement (a lightweight checklist in the Definition of Ready); keep a living model; reserve full-system modeling for major architectural shifts. Trigger on events (new integration, new data type, new trust boundary), not a calendar.

---

## 6. Secure SDLC & code review

### At which SDLC phases does security belong?
Requirements (security requirements/abuse cases), Design (threat modeling), Development (secure coding standards, SAST, peer review), Testing (DAST, manual pentest), Deployment (secure config, SCA for dependencies), Maintenance (patching, monitoring). The cost of a fix rises sharply the later it's found.

### What is shift-left / DevSecOps?
Moving security earlier: threat modeling at design, SAST + secret scanning on every commit, SCA in the pipeline, DAST in staging, security gates before release.

### SAST vs DAST vs IAST vs SCA?
- **SAST** - analyses source/bytecode without running it; catches code-level flaws early; high false positives; misses runtime/config.
- **DAST** - tests the running app from outside (Burp, ZAP); catches runtime/config; can't pinpoint the line or reach uncrawled code.
- **IAST** - instruments the running app during functional testing to combine both.
- **SCA** - scans third-party dependencies for known CVEs (Snyk, Dependabot, OWASP Dependency-Check).
Run all four in layers; add periodic manual pentest for business-logic gaps none catch.

### SAST vs SCA specifically?
SAST analyses code *you wrote*; SCA analyses dependencies *you consumed*. A clean SAST scan says nothing about a Log4Shell-style CVE in an imported library, and a clean SCA scan says nothing about SQLi in your own code - run both as distinct gates.

### How do you approach a secure code review?
1. Understand the app (architecture, entry points, roles, data flows). 2. SAST first pass (Semgrep, SonarQube). 3. Manually trace **sources -> sinks**: user input (params, headers, files) into dangerous functions (SQL, shell, file paths, template rendering, deserialization, redirects). 4. Check auth/authorization on every route, crypto use, secrets in code, sensitive-data logging, dependency versions. 5. Confirm exploitability before reporting; give the fixed code pattern.

### Dangerous functions in PHP/Laravel?
Raw SQL: `DB::raw()`, `whereRaw()`, `DB::select()` with concatenation. Command exec: `exec()`, `system()`, `shell_exec()`, `passthru()`. Code exec: `eval()`, `assert()`. Deserialization: `unserialize()`. File inclusion: `include`/`require` with user input. Output: Blade `{!! $var !!}` (unescaped) vs safe `{{ $var }}`. Mass assignment: `$guarded = []`.

### Dangerous sinks in JavaScript?
`innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `new Function`, `location`/`href` assignment with user input, jQuery `.html()`. Node: `child_process.exec`, `vm`, unsafe object merges (prototype pollution).

### Manual vs automated code review - which do you trust more?
Complementary. SAST is a fast first pass for known patterns at scale; manual review finds authorization gaps and business-logic flaws tools structurally can't reason about. Look at authentication/session handling and trust-boundary crossings first.

### Spot the bug: state-changing POST updating email from `$_POST` with no CSRF token.
CSRF - a logged-in victim visiting an attacker page auto-submits the form and their email is changed, enabling account takeover via password reset. Fix: synchroniser CSRF token validated server-side, `SameSite` cookie, and email-confirmation/re-auth for sensitive changes.

### How do you prioritise noisy SAST findings for a dev team?
Triage by severity x reachability (is the flagged path reachable from untrusted input?), suppress confirmed false positives at the *rule* level, and batch similar findings so the pattern is fixed once. Make SAST a PR-blocking gate only for high-confidence, high-severity rules - over-blocking trains devs to ignore it.

### Metrics to prove an AppSec program works?
Mean time to remediate by severity, % of critical/high fixed within SLA, trend of new-vs-recurring vulnerability classes, SAST/DAST/SCA coverage across the portfolio, % of releases with a threat-modeling review. Favour trends over point-in-time counts.
