# Source Code Audit (Manual & Automated) - Reference & Interview Prep

A source code audit (secure code review) reads the application from the inside:
instead of guessing at behaviour through a proxy, you trace untrusted input from
where it enters (sources) to where it causes harm (sinks) and check the
controls in between. It catches logic and crypto flaws black-box testing misses,
and it pinpoints the exact line to fix. The method blends **automated SAST** for
breadth with **manual review** for the bugs tools cannot understand (authz,
business logic, design). Findings still follow the
**What -> Why -> How -> Impact -> Mitigations** shape used across these notes.

Vuln classes and payloads live in [web-security.md](web-security.md) and
[payload-reference.md](../testing/payload-reference.md); pipeline/SAST tooling
also appears in [methodology-and-sdlc.md](methodology-and-sdlc.md).

---

## 1. Manual vs automated

| | Automated (SAST) | Manual review |
| --- | --- | --- |
| Good at | breadth, known injection/taint patterns, hardcoded secrets, fast re-runs | logic, authz, crypto misuse, design, chained issues |
| Weak at | business logic, authz, intent, novel patterns; false positives/negatives | breadth, speed on large codebases |
| Output | ranked candidate findings to verify | confirmed, context-aware findings |

Use SAST to triage and narrow; use manual review to confirm, find what tools
cannot, and judge real impact. Neither replaces the other.

## 2. The source-to-sink model
- **Source** - where untrusted data enters: request params, headers, cookies,
  file uploads, message queues, DB rows written by other users, env/CLI.
- **Sink** - where it becomes dangerous: SQL query, `exec`/`system`, HTML
  output, file path, deserializer, template, redirect, reflection.
- **Sanitizer/validator** - what should sit between them. A finding is a source
  that reaches a sink with no (or bypassable) sanitizer on the path.

**Worked trace.** `name = request.args.get("name")` (source) -> `q = "... WHERE name='%s'" % name` (tainted) -> `db.execute(q)` (sink). No parameterization on the path, so it is a confirmed SQL injection, not a candidate. A sanitizer for the wrong context does not count - HTML-encoding a value that is placed into a SQL string, or SQL-escaping one placed into HTML, leaves the real sink exploitable. Always check the encoding matches the sink.

## 3. What to look for (high-yield)
- **Injection sinks** - string-built SQL, `eval`/`exec`, command execution,
  template rendering of user data, dynamic file paths, unsafe deserialization.
- **AuthN/Z** - missing checks on an endpoint, checks done client-side only,
  IDOR (object id used without an ownership check), role checks that can be
  skipped, JWT validation that trusts `alg`/`none`.
- **Secrets & config** - hardcoded keys/passwords/connection strings, debug
  flags, permissive CORS, disabled TLS verification.
- **Crypto misuse** - home-grown crypto, ECB mode, static IV/salt, weak hashing
  for passwords (MD5/SHA1, no bcrypt/argon2), predictable randomness
  (`Math.random` for tokens).
- **Error handling** - stack traces to users, swallowed exceptions that skip
  security checks.
- **Dependencies (SCA)** - known-vulnerable libraries; check manifests/lockfiles.

## 4. How to run an audit
1. **Understand the app** - language/framework, entry points (routes,
   controllers, handlers), trust boundaries, data stores, auth model.
2. **Map sources and sinks** - list input entry points and dangerous functions
   for the stack.
3. **Automated pass** - run SAST (Semgrep/CodeQL) and SCA; collect candidates.
4. **Manual trace** - follow high-risk flows source -> sink; verify each SAST
   candidate (true/false positive) and review auth/logic by hand.
5. **Confirm & rate** - PoC where possible, assign severity/CVSS, name the exact
   file:line and the fix.

## 5. Interview-style answers
- **"SAST vs DAST?"** SAST reads code from the inside (no running app, finds the
  line, early in SDLC, false positives); DAST tests the running app from outside
  (real exploitability, no source, later). They are complementary; IAST/SCA sit
  alongside.
- **"How do you review a large codebase fast?"** Start at trust boundaries and
  entry points, grep dangerous sinks, run SAST to triage, then manually trace
  only the flows that reach a sink. Prioritise auth and injection.
- **"Biggest limitation of SAST?"** It does not understand intent - business
  logic and authorization flaws need a human.

## 6. Quick checklist
- [ ] Framework + entry points + trust boundaries mapped
- [ ] Sources and dangerous sinks enumerated for the stack
- [ ] SAST (Semgrep/CodeQL) + SCA run, candidates collected
- [ ] Injection sinks traced from source
- [ ] AuthN/Z and IDOR reviewed per endpoint
- [ ] Secrets/config/crypto/error-handling reviewed
- [ ] Each finding verified, rated, and pinned to file:line with a fix
