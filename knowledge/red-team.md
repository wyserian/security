# Red Teaming & Adversary Emulation - Reference & Interview Prep

Red teaming is goal-based adversary emulation: instead of enumerating every
vulnerability, a red team emulates a real threat actor to reach a defined
objective (domain admin, access to crown-jewel data, a specific transaction)
while staying stealthy, and tests people and process as much as technology. The
real deliverable is an attack narrative and the defender's detection/response
gaps, not just a findings list. Everything here assumes an authorized engagement
with signed rules of engagement.

Infrastructure attack detail (Active Directory, lateral movement, Windows
persistence/LOLBins) lives in
[network-and-fundamentals.md](network-and-fundamentals.md) and the testing-side
[network-infrastructure-security-testing.md](../testing/network-infrastructure-security-testing.md).

---

## 1. What red teaming is (and is not)

| | Vulnerability Assessment | Penetration Test | Red Team |
| --- | --- | --- | --- |
| Goal | catalogue weaknesses | exploit to prove impact | reach an objective like a real adversary |
| Scope | broad, known | defined systems | broad, often assumed-breach, multi-vector |
| Stealth | none | usually none | core - avoid detection |
| Tests | tech | tech | people + process + tech + detection |
| Output | list | exploited findings | attack narrative + detection gaps |

- **Purple team** - red and blue work together to improve detection in real time.
- **Assumed breach** - start with a foothold (a workstation/user) to test what an
  attacker does after initial access, without spending weeks on phishing.
- **Adversary emulation** - replicate a specific named threat actor's known TTPs.

## 2. The attack lifecycle
The Lockheed Martin Cyber Kill Chain and MITRE ATT&CK describe the same arc:

1. **Reconnaissance** - OSINT on people, tech, exposure.
2. **Resource development** - infrastructure, tooling, pretexts.
3. **Initial access** - phishing, exposed service, valid accounts, physical/SE.
4. **Execution & foothold** - run code, establish command-and-control (C2).
5. **Persistence** - survive reboots/credential changes.
6. **Privilege escalation** - local then domain.
7. **Defense evasion** - avoid AV/EDR and logging.
8. **Credential access** - dump/steal credentials and tickets.
9. **Discovery** - map the environment (users, hosts, trusts).
10. **Lateral movement** - pivot host to host toward the goal.
11. **Collection & exfiltration** - gather and (emulate) remove target data.
12. **Impact / objective** - achieve and evidence the agreed goal.

## 3. MITRE ATT&CK
A knowledge base of adversary **tactics** (the why - the columns above) and
**techniques** (the how). Red teams use it to plan and label TTPs; blue teams use
it to map detection coverage. Purple teaming is largely "do we detect this
technique?" walked tactic by tactic.

## 4. Key concepts
- **Initial access vectors** - spear-phishing (attachment/link), exposed/vulnerable
  external service, valid/leaked credentials, supply chain, and physical/social
  engineering (tailgating, pretext calls, rogue devices).
- **Command and control (C2)** - the channel back to compromised hosts. Common
  frameworks in authorized engagements include Cobalt Strike, Sliver, Mythic and
  Havoc; traffic is often blended into HTTPS/DNS/known services. These are
  dual-use tools used only within an authorized scope.
- **Living off the land (LOLBins)** - use built-in tools (PowerShell, WMI, certutil,
  rundll32) instead of dropping malware, to blend in. Windows internals and these
  binaries are catalogued in the network/infrastructure guide.
- **Defense evasion / OPSEC** - minimise footprint and noisy actions, avoid
  detection by AV/EDR and SIEM; operational security protects the engagement and
  the client. (Covered at concept level only here.)
- **Credential access & AD attacks** - dump credentials/tickets, then:
  Kerberoasting and AS-REP roasting (crack tickets offline), Pass-the-Hash and
  Pass-the-Ticket (reuse an NTLM hash or Kerberos ticket), Golden Ticket (forge
  TGTs with the KRBTGT hash = full domain), Silver Ticket (forge one service
  ticket), DCSync (impersonate DC replication to pull hashes), and delegation/ACL
  abuse. AD *concepts and enumeration* are in
  [network-and-fundamentals.md](network-and-fundamentals.md#5-active-directory).

## 5. Rules of engagement & safety
- Signed authorization, scope, objectives, timeframe, and legal sign-off before
  anything starts.
- **Deconfliction** - a channel so the blue team/IT can check whether suspicious
  activity is the red team.
- Safe-word / stop conditions; no real destruction; emulate exfiltration with
  benign data; protect any data accessed.
- Document everything for a clean after-action and retest.

## 6. Reporting
- **Attack narrative** - the path taken, step by step, mapped to ATT&CK.
- **Detection gaps** - what the blue team saw vs missed, and where to add
  detection/response.
- **Root causes & recommendations** - not just "patch X" but the systemic issues
  (flat network, weak segmentation, no egress control, poor logging).

## 7. Interview-style answers
- **"Red team vs pentest?"** A pentest finds and proves as many vulnerabilities as
  possible in a defined scope; a red team emulates a real adversary to reach an
  objective stealthily, testing detection and response (people/process) too.
- **"What is assumed breach and why use it?"** Start from a foothold rather than
  spending the engagement on initial access, to focus on post-exploitation and
  detection of lateral movement and privilege escalation.
- **"What is purple teaming?"** Red and blue collaborating to validate and improve
  detections against specific ATT&CK techniques.
- **"Why is C2 traffic hard to catch?"** It blends into normal protocols
  (HTTPS/DNS), uses jitter and legitimate-looking domains, and relies on LOLBins
  so there is little malware to flag.
- **"Cyber Kill Chain vs MITRE ATT&CK?"** The Kill Chain is a linear 7-stage
  model of an intrusion (recon -> actions on objectives); ATT&CK is a non-linear
  matrix of tactics (the goals) and hundreds of concrete techniques (the methods)
  observed in the wild. The Kill Chain frames the arc; ATT&CK gives the detailed,
  detection-mappable TTPs.
- **"What is a TTP?"** Tactics, Techniques and Procedures - the *what* an actor
  is trying to do (tactic), the *how* (technique), and the specific
  implementation (procedure). Emulating a named actor means replicating its TTPs.
- **"IOC vs IOA?"** An Indicator of Compromise is a forensic artifact of a past
  breach (a hash, IP, domain); an Indicator of Attack is behaviour in progress
  (a process spawning PowerShell that reaches out to the internet). IOAs catch
  novel attacks that IOC signatures miss - which is why LOLBin-heavy red teaming
  stresses behavioural detection.
- **"How do red teams evade EDR (conceptually)?"** Prefer living-off-the-land
  over dropped binaries, run in memory, and minimise noisy actions - so there is
  behaviour to detect rather than files to signature. The point is to measure the
  blue team's behavioural coverage, not to ship evasion tooling.

## 8. Quick checklist
- [ ] Signed ROE, scope, objective, timeframe, deconfliction channel
- [ ] Recon/OSINT on people, tech, external exposure
- [ ] Initial access plan (phishing / exposed service / valid accounts / SE)
- [ ] Foothold + C2, persistence
- [ ] Privilege escalation (local -> domain)
- [ ] Credential access + discovery + lateral movement toward the objective
- [ ] Objective achieved and evidenced (benign exfil)
- [ ] ATT&CK-mapped narrative + detection gaps + systemic recommendations
