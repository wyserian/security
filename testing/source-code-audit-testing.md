# Source Code Audit (Manual & Automated) - Practitioner Reference

Companion to the per-domain testing guides. Covers the secure-code-review flow: scoping a codebase, the automated (SAST/SCA) and manual passes, the source-to-sink tracing method, language-specific sinks, and how to turn candidates into confirmed, line-level findings. Use this alongside the web/API guides for the vulnerability details and [sdlc-security-testing.md](sdlc-security-testing.md) for where this fits in the pipeline.

> Concepts/interview framing: [../knowledge/source-code-audit.md](../knowledge/source-code-audit.md) | vuln detail: [web-security-testing.md](web-security-testing.md) / [api-security-testing.md](api-security-testing.md) | payloads: [payload-reference.md](payload-reference.md) | full tool inventory: [tools-reference.md](tools-reference.md).

---

## 1. Methodology

Code review beats black-box testing on coverage (you see every path, not just the ones you guessed) and loses on runtime realism (you may flag code that is unreachable in production). Combine both: use the code to find candidates, use a running build to confirm them.

1. **Scope** - repos, branch/commit (pin it - code moves), languages/frameworks, what is in and out, and access to build/run the app (lets you resolve dependencies and confirm findings dynamically later).
2. **Orientation** - before reading line by line, build a map: entry points (routes, controllers, handlers, message consumers, scheduled jobs), trust boundaries (where external data crosses into the app), data stores, the authentication and authorization model, and the third-party dependency list. You are looking for where untrusted data enters and where it does something dangerous.
3. **Automated pass** - SAST + SCA + secret scan for breadth and to point you at hotspots.
4. **Manual pass** - trace high-risk flows source -> sink; verify every SAST candidate; and review by hand the things SAST cannot judge: authorization, business logic, and crypto.
5. **Report** - confirmed findings at `file:line`, severity/CVSS, and the concrete fix; note false positives you suppressed and why.

---

## 2. Automated pass (SAST / SCA / secrets)

| Tool | Type | Notes |
| --- | --- | --- |
| Semgrep | SAST | fast, rule-based, many languages, custom rules in YAML |
| CodeQL | SAST | query/taint engine, deep inter-procedural analysis, GitHub-native |
| SonarQube | SAST | quality + security, CI dashboards |
| Bandit | SAST | Python |
| gosec | SAST | Go |
| Brakeman | SAST | Ruby on Rails |
| Snyk / OWASP Dependency-Check | SCA | known-vulnerable dependencies |
| trufflehog / gitleaks | secrets | code + full git history |

Run these first for breadth. Treat output as candidates, not findings - SAST reports taint it cannot prove is reachable (false positives) and misses logic and authorization flaws entirely (false negatives). Tune rules, triage, and keep the signal.

### Writing a quick custom rule (Semgrep)
When you spot a stack-specific dangerous pattern, codify it so it is flagged everywhere. Example - flag string-formatted SQL:
```yaml
rules:
  - id: raw-sql-format
    patterns:
      - pattern: $CUR.execute("..." % ...)
    message: Possible SQL injection - parameterize the query
    languages: [python]
    severity: ERROR
```
CodeQL is the heavier tool when you need to follow tainted data across functions and files; Semgrep is the fast one for syntactic patterns and secrets.

---

## 3. Manual pass - source-to-sink tracing

The core technique: untrusted data (a **source**) is dangerous only when it reaches an operation that acts on it (a **sink**) without correct sanitization in between.

- **Sources:** request params, headers, cookies, path segments, uploaded files, queue/stream messages, webhook bodies, and database fields written by other users (stored/second-order).
- **Sinks:** the exec/query/render/deserialize operations listed below, per language.
- **Method:** for each reachable sink, trace backward. Does untrusted data reach it? Is there a sanitizer on *every* path, and is it correct and non-bypassable (right encoding for the context, no way around it)? A sanitizer for the wrong context (HTML-encoding data placed into a JS string) is no sanitizer.

### Worked example (Python / Flask)
```
@app.route("/report")
def report():
    name = request.args.get("name")        # SOURCE: user-controlled
    q = "SELECT * FROM users WHERE name = '%s'" % name   # tainted string built
    return db.execute(q)                    # SINK: raw SQL execution -> SQLi
```
Trace: `request.args` -> `name` -> string-formatted into `q` -> `db.execute`. No parameterization on the path, so this is a confirmed injection, not a candidate. Fix: parameterized query (`db.execute("... WHERE name = ?", [name])`).

### What to review by hand (SAST is blind here)
- **Authorization:** is there an ownership/role check on every object and function, or only an authentication check? IDOR lives here - an object id used to fetch data without verifying the caller owns it.
- **Business logic:** multi-step flows, price/quantity/state manipulation, race conditions, workflow bypass.
- **Crypto & secrets:** weak algorithms (MD5/SHA1 for passwords, ECB, hardcoded IV/keys), home-grown crypto, secrets in source or config.
- **Config & error handling:** debug mode on, verbose errors, insecure defaults, missing security headers set in code.

### Dangerous sinks by language (grep targets)
| Language | Injection / exec | Deserialize | Other |
| --- | --- | --- | --- |
| Java | `Statement.execute`, `Runtime.exec`, `ProcessBuilder` | `ObjectInputStream.readObject`, `XMLDecoder` | reflection, EL, SpEL, `@RequestMapping` authz |
| Python | `os.system`, `subprocess(..., shell=True)`, `eval`/`exec`, raw cursor `%`/f-string | `pickle.loads`, `yaml.load` | `jinja2`/`render_template_string` from input |
| JS / Node | `child_process.exec`, `eval`, `Function()` | - | `innerHTML`, `dangerouslySetInnerHTML`, template concat, `vm` |
| PHP | `system`, `exec`, `shell_exec`, `eval`, backticks | `unserialize` | `include`/`require` with input, `extract` |
| C# / .NET | `SqlCommand` string concat, `Process.Start` | `BinaryFormatter`, `LosFormatter` | `XmlSerializer`, reflection |
| Go | `exec.Command` with shell, `db.Query` concat | `gob` | `text/template` rendered into HTML |
| Ruby | `system`, backticks, `eval`, raw `where("...#{}")` | `Marshal.load`, `YAML.load` | `send`/`public_send`, `constantize` |

---

## 4. From candidate to confirmed finding
- **Reproduce:** craft the input that reaches the sink; build a PoC in a running instance where possible. A sink you cannot reach from a source is informational, not a vulnerability.
- **Rate:** severity/CVSS based on real impact and reachability (authentication required? internet-facing? what data?).
- **Pin:** the exact `file:line`, the tainted path from source to sink, and the concrete fix - parameterize, context-encode, validate, add the authorization check, or replace the dangerous primitive. A fix the developer can paste beats a lecture.

---

## 5. Tools & checklist
**SAST:** Semgrep, CodeQL, SonarQube, Bandit, gosec, Brakeman. **SCA:** Snyk, OWASP Dependency-Check. **Secrets:** trufflehog, gitleaks. **Helpers:** grep/ripgrep, IDE call-hierarchy / "find references", `git log`/blame for who-changed-what context. (Full inventory in [tools-reference.md](tools-reference.md).)

**Review checklist:**
- [ ] scope + branch/commit pinned + build access
- [ ] entry points + trust boundaries mapped
- [ ] SAST + SCA + secret scan run
- [ ] sources/sinks enumerated per language
- [ ] injection sinks traced from source
- [ ] authz / IDOR / business logic reviewed manually
- [ ] crypto / config / error-handling reviewed
- [ ] every candidate verified (true vs false positive)
- [ ] findings at file:line + CVSS + fix + retest

## Quick mental model
Follow untrusted data from where it enters to where it hurts. SAST finds the candidates; you confirm the path, judge the impact, and name the line to fix.
