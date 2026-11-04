# Application Architecture & Security Design Review - Practitioner Reference

Companion to the secure-SDLC and source-code-audit guides. Covers how to run a
security architecture review and threat-modeling engagement: gathering design
inputs, drawing the system and its trust boundaries, applying STRIDE to find
design-level weaknesses, and reporting prioritized design changes. This is a
design-level activity - the output is missing/weak controls and risks, not a
list of exploited bugs.

> Concepts/interview framing: [../knowledge/application-architecture-review.md](../knowledge/application-architecture-review.md) | secure SDLC: [sdlc-security-testing.md](sdlc-security-testing.md) | code-level follow-up: [source-code-audit-testing.md](source-code-audit-testing.md) | full tool inventory: [tools-reference.md](tools-reference.md).

---

## 1. Methodology

1. **Scope & inputs** - gather architecture docs, DFDs, API specs, infra
   diagrams, auth design, data classification; interview the team for what the
   docs omit.
2. **Model the system** - draw components, data stores, external entities, data
   flows, and trust boundaries (a DFD).
3. **Enumerate threats** - apply STRIDE per component / cross-boundary flow
   (optionally PASTA for risk-centric, LINDDUN for privacy).
4. **Assess controls** - for each threat, is there a control, at the right place,
   and is it sufficient?
5. **Rate & recommend** - risk-rank gaps, propose design changes, prioritize.
6. **Validate** - confirm fixes are feasible and re-review the revised design.

---

## 2. Gathering inputs
- Architecture / deployment diagrams, network topology, infra-as-code.
- API/interface specs, authentication and session design, authorization model.
- Data classification (what is sensitive) and where it lives/flows.
- Third-party/managed dependencies and the trust placed in them.
- Interviews - diagrams lie by omission; ask how auth, secrets, and inter-service
  calls actually work.

## 3. Drawing the model (DFD)
Elements: external entities, processes, data stores, data flows, and trust
boundaries. Keep it at the level where boundaries are visible (client <-> API
<-> service <-> data store <-> third party). The boundary crossings are the
review's focus - each should have authentication, authorization, validation and
encryption as appropriate.

## 4. Applying STRIDE
For each element/flow crossing a boundary, walk the six categories:

| Threat | Ask |
| --- | --- |
| Spoofing | How is each side's identity proven? |
| Tampering | Is data integrity protected in transit and at rest? |
| Repudiation | Are security-relevant actions logged and attributable? |
| Information disclosure | Is sensitive data encrypted and access-controlled? |
| Denial of service | Are resources bounded / rate-limited? |
| Elevation of privilege | Is every access authorized (complete mediation)? |

Record each credible threat, whether a control exists, and the gap.

### Worked example - "browser -> API login" flow
- **Spoofing:** can someone impersonate the user (credential stuffing, no MFA) or the API (no TLS/cert pinning)? Control: strong auth + MFA, TLS.
- **Tampering:** can the request/response be modified in transit? Control: TLS; integrity on sensitive fields.
- **Repudiation:** is the login attempt logged with source and outcome? Control: auth audit log.
- **Information disclosure:** does an error distinguish "user not found" from "wrong password" (user enumeration)? Are tokens returned in the URL? Control: generic errors, token in body/header.
- **Denial of service:** is login rate-limited and lockout-protected? Control: throttling + backoff.
- **Elevation of privilege:** does the issued token's scope match the user's role, checked server-side on every later call? Control: server-side authz, least-privilege tokens.

A single flow usually surfaces several real gaps - that is the point of walking all six categories at every boundary rather than trusting the diagram.

## 5. Control assessment checklist (by boundary)
- **AuthN** - every boundary authenticates both ends (no implicit inter-service
  trust; mutual TLS / signed tokens for service-to-service).
- **AuthZ** - server-side, checked on every request, least privilege.
- **Validation** - input validated server-side at each boundary.
- **Crypto** - TLS in transit, encryption at rest for sensitive data, proper key
  management.
- **Secrets** - vault, rotation, no hardcoded credentials.
- **Isolation** - segmentation, least-privilege IAM, limited blast radius.
- **Observability** - logging/monitoring/alerting at boundaries.
- **Defaults** - secure defaults, minimized surface, defense in depth.

## 6. Rating & reporting
- Rank risks (likelihood x impact; DREAD or a simple High/Med/Low) and tie each
  to a concrete design change.
- Separate "must fix before ship" (missing trust boundary, plaintext PII) from
  hardening.
- Output: the model/DFD, the threat list with STRIDE mapping, gaps, and
  prioritized recommendations. Feed code-level follow-ups to
  [source-code-audit-testing.md](source-code-audit-testing.md).

## 7. Tools & checklist
**Modeling:** OWASP Threat Dragon, Microsoft Threat Modeling Tool, draw.io,
pytm (threat-model-as-code). **Reference:** STRIDE, PASTA, LINDDUN, OWASP ASVS,
attack trees. (Full inventory in [tools-reference.md](tools-reference.md).)

**Checklist:**
- [ ] scope + design inputs + interviews
- [ ] DFD with trust boundaries
- [ ] STRIDE per component/flow
- [ ] control present-correct-sufficient per threat
- [ ] authN/authZ at every boundary
- [ ] crypto in transit + at rest
- [ ] secrets management
- [ ] isolation + least privilege
- [ ] observability at boundaries
- [ ] risks ranked + design changes + re-review.

## Quick mental model
Draw the system, mark where trust changes hands, and at each crossing ask the
six STRIDE questions. A finding is a boundary missing a control it should have.
