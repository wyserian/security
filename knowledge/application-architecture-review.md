# Application Architecture & Security Design Review - Reference & Interview Prep

An architecture review assesses security at the design level: data flows, trust
boundaries, components and their interactions - before (or alongside) looking at
code or a running app. Done early it catches whole classes of flaw that no
amount of pentesting a finished build can fix cheaply (missing authentication
between services, a trust boundary in the wrong place, secrets with no store).
Its core technique is **threat modeling**. Unlike the vuln notes, findings here
are design weaknesses and missing controls rather than single exploitable bugs.

Pairs with the secure SDLC in [methodology-and-sdlc.md](methodology-and-sdlc.md);
the concrete vulnerabilities a weak design leads to are in the per-domain notes.

---

## 1. What it covers
- **Components & trust boundaries** - clients, services, data stores, third
  parties, and where control/trust changes hands (the boundaries are where
  controls must sit).
- **Data flows** - how data moves between components, its sensitivity, and where
  it is validated, authenticated and encrypted.
- **Controls** - authentication, authorization, input validation, encryption
  (in transit and at rest), secrets management, logging/monitoring, isolation.
- **Assumptions** - what each component trusts about the others, and whether
  that trust is justified.

## 2. Threat modeling

### The four questions
1. What are we building? (diagram it)
2. What can go wrong? (enumerate threats)
3. What are we going to do about it? (mitigations)
4. Did we do a good job? (validate)

### STRIDE
A checklist of threat types to apply per component/flow:

| Threat | Violates | Example |
| --- | --- | --- |
| Spoofing | Authentication | impersonating a user/service |
| Tampering | Integrity | modifying data in transit or at rest |
| Repudiation | Non-repudiation | denying an action, no audit trail |
| Information disclosure | Confidentiality | leaking data |
| Denial of service | Availability | exhausting a resource |
| Elevation of privilege | Authorization | gaining higher rights |

Other frameworks: **PASTA** (risk-centric, business-aligned), **DREAD** (rating),
**attack trees** (goal decomposition), **LINDDUN** (privacy).

### Data flow diagrams (DFDs)
Draw external entities, processes, data stores, and data flows; mark trust
boundaries. Apply STRIDE to each element crossing a boundary. The boundary is
where you expect authentication, authorization and validation.

## 3. Common architecture-level findings
- **Missing or weak trust boundaries** - services that trust each other with no
  authentication ("flat" internal network), or client-side trust for a
  server-side decision.
- **Secrets with no management** - credentials in config/code, no vault/rotation.
- **No defense in depth** - a single control (e.g. the gateway) is the only line;
  past it, nothing checks.
- **Unencrypted sensitive flows / storage** - plaintext internal traffic, no
  encryption at rest for PII.
- **Weak isolation / blast radius** - one compromised component reaches
  everything (over-broad network and IAM).
- **No logging/monitoring at boundaries** - attacks and abuse go unseen.
- **Insecure defaults and unnecessary exposure** - debug endpoints, admin
  surfaces, overly broad APIs.

## 4. Principles to check against
Least privilege, defense in depth, fail securely, complete mediation (check
every access), secure defaults, separation of duties, minimize attack surface,
and no "security by obscurity" as the only control.

## 5. Interview-style answers
- **"Why review architecture if you can pentest?"** Design flaws are cheapest to
  fix early and some cannot be patched late (a missing trust boundary needs
  re-architecting). Reviews find missing controls a pentest of a finished build
  cannot economically address.
- **"What is STRIDE?"** A per-component threat checklist - Spoofing, Tampering,
  Repudiation, Information disclosure, DoS, Elevation of privilege - mapped to
  the security properties each violates.
- **"Where do controls belong?"** At trust boundaries - authenticate, authorize
  and validate wherever trust changes hands.
- **"STRIDE vs PASTA vs DREAD?"** STRIDE enumerates *threat types* per component;
  PASTA is a seven-stage, risk- and business-centric *process*; DREAD is a
  *scoring* scheme (Damage, Reproducibility, Exploitability, Affected users,
  Discoverability). Use STRIDE to find threats, DREAD/CVSS to rate them, PASTA
  when the org wants business-aligned risk.
- **"What exactly is a trust boundary?"** A line where the level of trust
  changes - user to app, app to database, your service to a third party, one
  tenant to another. Data crossing it must be authenticated, authorized and
  validated, because what is safe on one side is attacker-controlled on the other.
- **"How do you prioritize threat-model findings?"** By risk (likelihood x
  impact) and by cost-to-fix-later: a missing trust boundary or plaintext PII is
  "fix before ship" because retrofitting is expensive; hardening items can be
  scheduled. Tie each to one concrete design change.

## 6. Quick checklist
- [ ] Architecture + data-flow diagram with trust boundaries
- [ ] STRIDE applied per component / cross-boundary flow
- [ ] AuthN/AuthZ present at each boundary (no implicit inter-service trust)
- [ ] Encryption in transit and at rest for sensitive data
- [ ] Secrets management (vault, rotation, no hardcoding)
- [ ] Isolation / blast-radius and least privilege
- [ ] Logging/monitoring at boundaries
- [ ] Secure defaults, minimized surface, defense in depth
- [ ] Findings mapped to design changes + priorities
