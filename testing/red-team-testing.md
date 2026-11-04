# Red Team Operations & Adversary Emulation - Practitioner Reference

Companion to the network/infrastructure and DevSecOps guides. Covers running an
authorized red team engagement end to end: planning and rules of engagement,
reconnaissance, initial access, foothold and C2, post-exploitation toward an
objective, and reporting against MITRE ATT&CK. This is adversary emulation under
signed authorization - techniques are described at a methodology level and tied
to detection, not as weaponized payloads.

> Concepts/interview framing: [../knowledge/red-team.md](../knowledge/red-team.md) | AD / lateral movement / Windows internals: [network-infrastructure-security-testing.md](network-infrastructure-security-testing.md) | initial-access payload context: [payload-reference.md](payload-reference.md) | full tool inventory: [tools-reference.md](tools-reference.md) | methodology/CVSS/reporting: [sdlc-security-testing.md](sdlc-security-testing.md).

---

## 1. Methodology (ATT&CK-aligned phases)

1. **Planning & ROE** - objective, scope, timeframe, legal sign-off,
   deconfliction channel, stop conditions.
2. **Reconnaissance** - OSINT and external enumeration.
3. **Initial access** - gain the first foothold.
4. **Foothold & C2** - establish and stabilise command and control.
5. **Post-exploitation** - persistence, privesc, credential access, discovery,
   lateral movement toward the objective.
6. **Actions on objective** - collection and (emulated) exfiltration; evidence.
7. **Reporting & purple-team** - narrative, detection gaps, remediation, retest.

---

## 2. Reconnaissance
- **OSINT:** employees and emails (LinkedIn, theHarvester, hunter), tech stack,
  breached-credential exposure, code/secret leaks (GitHub, gitleaks).
- **External enumeration:** subdomains and exposed services (amass, subfinder,
  httpx, Shodan), login portals, VPN/webmail, cloud assets.
- Output: a target map and candidate initial-access paths.

## 3. Initial access (common vectors)
- **Phishing / social engineering** - pretext, payload or credential-harvest
  page (with client approval of the pretext); Gophish for campaigns.
- **Exposed/vulnerable service** - exploit an internet-facing app or service.
- **Valid accounts** - leaked/sprayed credentials against external auth
  (password spraying with lockout awareness).
- **Physical / rogue device** - where in scope.
Map the chosen vector to ATT&CK and record what a defender could have seen.

## 4. Foothold, C2 and OPSEC
- Establish C2 over blended channels (HTTPS/DNS). Authorized-engagement
  frameworks: Cobalt Strike, Sliver, Mythic, Havoc. Configure redirectors, domain
  fronting/known-good domains, and callback jitter to be realistic.
- Prefer living-off-the-land (PowerShell, WMI, built-in binaries) over dropping
  tooling, to emulate a real actor and exercise EDR detection.
- OPSEC: minimise noisy actions, stage from memory where possible, and log your
  own actions for deconfliction. (Operational evasion specifics are intentionally
  kept high-level; this is for authorized testing and detection improvement.)

## 5. Post-exploitation
This phase sequences the adversary TTPs toward the objective. AD *concepts and
enumeration* (what AD is, ports, recon with smbclient/ldapsearch/kerbrute, and
the admin tooling) stay in
[network-infrastructure-security-testing.md](network-infrastructure-security-testing.md#6-active-directory);
the attack execution below lives here.

- **Persistence** - survive reboot/credential reset: registry Run keys, scheduled
  tasks, services, WMI event subscriptions, and AD objects (new accounts, ACL
  backdoors, AdminSDHolder, DCShadow). Windows internals/LOLBins catalogued in the
  network-infra guide section 9.
- **Privilege escalation** - local (winPEAS, service/registry misconfig,
  unquoted paths) then domain.
- **Credential access** - dump LSASS/SAM and tickets (Mimikatz, Rubeus,
  Impacket `secretsdump`); **Kerberoasting** (crack service-account tickets
  offline), **AS-REP roasting** (accounts with pre-auth disabled).
- **AD domain attacks:**
    - **Pass-the-Hash (PtH)** - authenticate with an NTLM hash, no password.
    - **Pass-the-Ticket (PtT)** - reuse/inject a Kerberos ticket to impersonate.
    - **Golden Ticket** - forge TGTs with the KRBTGT hash (full domain compromise).
    - **Silver Ticket** - forge a service ticket for one service.
    - **DCSync** - impersonate DC replication to pull NTLM/KRBTGT hashes.
    - **Delegation abuse / ACL attacks** - unconstrained/constrained delegation,
      vulnerable GPOs, misconfigured OUs, weak ACLs.
- **Discovery** - BloodHound/SharpHound to map attack paths to the objective.
- **Lateral movement** - PtH/PtT, WinRM, PsExec, SMB, RDP, DCOM (over C2).
- **Collection & exfiltration** - gather the agreed target data; emulate exfil
  with benign data over a monitored channel.

## 6. Reporting & purple team
- **Attack narrative** mapped to ATT&CK tactics/techniques, with timestamps for
  deconfliction and blue-team correlation.
- **Detection and response gaps** - which techniques were seen, missed, or slow;
  recommended detections per technique.
- **Systemic root causes** - segmentation, egress control, logging, least
  privilege - over one-off patches.
- Offer a purple-team replay of missed techniques.

## 7. Tools & checklist
**Recon/OSINT:** theHarvester, amass, subfinder, httpx, Shodan, gitleaks.
**Initial access:** Gophish, Metasploit, service-specific exploits. **C2
(authorized):** Cobalt Strike, Sliver, Mythic, Havoc. **AD/post-ex:** BloodHound/
SharpHound, Mimikatz, Rubeus, Impacket, CrackMapExec, winPEAS. (Full inventory in
[tools-reference.md](tools-reference.md); AD detail in
[network-infrastructure-security-testing.md](network-infrastructure-security-testing.md).)

**Checklist:**
- [ ] signed ROE + scope + objective + deconfliction + stop conditions
- [ ] recon/OSINT + external enumeration
- [ ] initial-access vector chosen and ATT&CK-mapped
- [ ] foothold + stable C2 + OPSEC/logging
- [ ] persistence
- [ ] privesc (local -> domain)
- [ ] credential access + discovery (BloodHound)
- [ ] lateral movement to objective
- [ ] objective evidenced + benign exfil
- [ ] ATT&CK narrative + detection gaps + systemic fixes + purple-team replay.

## Quick mental model
Pick an objective and emulate a real adversary to reach it quietly. Get in,
establish C2, move toward the goal using living-off-the-land and known AD
techniques, and measure what the defenders detected - that gap is the product.
