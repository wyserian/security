# Networking, Crypto & Cloud Fundamentals - Interview Q&A

The basics Indian VAPT consultancies open with before going deep, plus cloud fundamentals. Keep each answer to one or two lines unless asked to expand.

---

## 1. Networking basics

### What happens when you type a URL and hit Enter?
Browser cache check -> DNS resolution (recursive -> root -> TLD -> authoritative) -> TCP three-way handshake -> TLS handshake (if HTTPS) -> HTTP request -> server responds -> browser parses HTML/CSS/JS, loads sub-resources, renders. Security touchpoints at each hop: DNS spoofing/DNSSEC, SYN flood/spoofing, TLS cert validation/MITM, HTTP security headers.

### TCP three-way handshake? TCP vs UDP?
SYN -> SYN-ACK -> ACK. TCP is connection-oriented and reliable (HTTP, SSH); UDP is connectionless and faster (DNS, streaming). Follow-up: a SYN flood sends many SYNs and never completes the handshake, exhausting the half-open backlog = DoS; mitigate with SYN cookies and rate limiting.

### Common ports?
21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 143 IMAP, 443 HTTPS, 445 SMB, 1433 MSSQL, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 6379 Redis, 8080 alt-HTTP, 27017 MongoDB.

### The OSI model, and where attacks map?
Seven layers: 1 Physical, 2 Data Link (MAC/switches), 3 Network (IP/routing), 4 Transport (TCP/UDP), 5 Session, 6 Presentation (TLS/encoding), 7 Application (HTTP/DNS). Mapping attacks to layers: L2 ARP spoofing/MAC flooding, L3 IP spoofing/ICMP, L4 SYN flood/port scanning, L6 TLS stripping/weak ciphers, L7 the web/API attacks. TCP/IP collapses this into Link/Internet/Transport/Application. Useful for reasoning about where a control (or an attack) actually sits.

### Layer-2 attacks (ARP spoofing, MAC flooding, VLAN hopping)?
On a local network there is no authentication at layer 2, so:
- **ARP spoofing/poisoning** - send forged ARP replies so victims map the gateway's IP to your MAC; you become a man-in-the-middle and can sniff/modify traffic (tools: `ettercap`, `bettercap`, `arpspoof`). The basis of LAN MITM and SSL-strip attempts.
- **MAC flooding** - overflow the switch's CAM table so it fails open and floods frames to all ports, letting you sniff traffic a switch would normally isolate.
- **VLAN hopping** - reach a VLAN you shouldn't via switch-spoofing (DTP) or double-tagging (802.1Q).
- **Fixes:** dynamic ARP inspection, DHCP snooping, port security (limit MACs), disable DTP/auto-trunking, and encrypt traffic (TLS) so MITM yields ciphertext.

### Nmap - TCP connect vs SYN scan, and key flags?
Connect scan (`-sT`) completes the handshake - no root needed but noisy. SYN scan (`-sS`) sends SYN and resets after SYN-ACK - faster, stealthier, needs root. Also: `-sV` (service versions), `-O` (OS), `-p-` (all ports), `-sC` (default scripts), `-sU` (UDP).

### HTTP methods and status codes?
GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE (TRACE enabled -> cross-site tracing risk). 200 OK, 301/302 redirect, 400 bad request, 401 unauthenticated, 403 forbidden, 404 not found, 405 method not allowed, 429 too many requests, 500 server error, 502/503 gateway/unavailable.

### 401 vs 403?
401 = not authenticated (no/bad credentials). 403 = authenticated but not authorised.

### IDS vs IPS?
IDS detects and alerts (passive). IPS is inline and can block/drop traffic (active).

### Man-in-the-middle attack?
Attacker sits between client and server, relaying/altering traffic. Enabled by no/weak TLS, untrusted CAs, ARP/DNS spoofing. Defences: TLS with proper cert validation, HSTS, certificate pinning, secure networks.

---

## 2. Cryptography & encoding

### Encoding vs encryption vs hashing?
Encoding changes format, no key, fully reversible (Base64, URL encoding) - zero confidentiality. Encryption needs a key and is reversible with it (AES, RSA). Hashing is one-way (SHA-256, bcrypt). Treating Base64 as security is a classic mistake.

### Symmetric vs asymmetric encryption?
Symmetric = one shared key (AES), fast, for bulk data. Asymmetric = public/private key pair (RSA, ECC), for key exchange and signatures. TLS uses asymmetric to agree a session key, then symmetric for the data.

### What is salting?
A random per-password value added before hashing, so identical passwords produce different hashes and precomputed rainbow tables don't work.

### How should passwords be stored?
A slow, salted, purpose-built hash - Argon2id (preferred), bcrypt, or scrypt - with a tuned work factor. Never plain/unsalted MD5/SHA, never reversible encryption.

### Why is unsalted MD5 for passwords bad, and the fix?
MD5 is fast (billions/sec on a GPU) and unsalted, so rainbow tables and mass brute force are trivial, and identical passwords hash identically (reveals reuse). Fix: Argon2id/bcrypt/scrypt with unique salts.

### Explain the TLS handshake and common SSL/TLS findings.
Client hello -> server hello + certificate -> key exchange -> both derive a session key -> encrypted traffic. Findings: TLS 1.0/1.1 enabled, weak ciphers (RC4, 3DES, old CBC), missing forward secrecy (static RSA key exchange), expired/self-signed certs, missing HSTS. Tools: testssl.sh, sslscan, Nmap `ssl-enum-ciphers`.

### What is Perfect Forward Secrecy?
Ephemeral key exchange (ECDHE) so each session has a unique key - compromising the server's long-term private key doesn't decrypt previously captured traffic.

### Why can an HTTPS site still get hacked?
TLS protects data *in transit* only; it says nothing about application logic, server config, or data at rest. A perfectly TLS-configured site can still be SQL-injectable - the payload just rides inside the encrypted channel.

---

## 3. Core security concepts

### CIA triad? AAA?
Confidentiality, Integrity, Availability. Authentication, Authorization, Accounting. Map every finding to the triad leg it breaks.

### Vulnerability vs threat vs risk vs exploit?
Vulnerability = a weakness. Threat = something that can exploit it. Exploit = the method/code that does. Risk = likelihood x impact.

### False positive vs false negative?
FP = tool flags a non-issue (wastes triage time). FN = tool misses a real vuln (worse - false confidence). Manual verification reduces both.

### Same-Origin Policy and CORS?
SOP stops a page reading responses from another origin (scheme+host+port). CORS is how a server deliberately relaxes SOP with `Access-Control-Allow-*` headers. (Testing detail in [web-security.md](web-security.md).)

### MITRE ATT&CK?
A knowledge base of real-world adversary tactics, techniques and procedures across the attack lifecycle. Know the tactic names: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Exfiltration, Impact.

---

## 4. Cloud fundamentals

### Shared responsibility model?
The provider secures the cloud (physical infra, hypervisor); the customer secures what's *in* the cloud - OS/network config, data, IAM, application. The split shifts with IaaS -> PaaS -> SaaS, but things like an S3 bucket policy are always the customer's job.

### Common cloud misconfigurations?
Publicly readable/writable storage buckets (S3/Blob/GCS), security groups open to `0.0.0.0/0` on sensitive ports, over-permissive IAM roles, unencrypted data at rest, disabled logging (CloudTrail). Find public buckets with `aws s3 ls s3://<bucket> --no-sign-request`.

### How does SSRF become critical in the cloud (IMDS)?
Via the instance metadata service: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` hands out temporary IAM credentials to anything that can reach it from the instance. IMDSv1 is unauthenticated (trivially SSRF-able); IMDSv2 requires a PUT-obtained session token, which most simple SSRF payloads can't do. **Fix:** enforce IMDSv2 and fix the underlying SSRF.

### IAM least-privilege review - what do you look for?
Wildcards (`"Action":"*","Resource":"*"`), unused admin grants, and privilege-escalation combos like `iam:PassRole` + `ec2:RunInstances`. Right-size against actual CloudTrail usage; tools: IAM Access Analyzer, Prowler, ScoutSuite.

### Security group vs NACL (AWS)?
Security groups are stateful, instance-level, allow-rules only. NACLs are stateless, subnet-level, with allow *and* deny rules where order matters. A security group open to the world on 22/3389 is directly exploitable regardless of NACLs.

### Securing secrets in CI/CD and cloud-native apps?
Use a secrets manager (Vault, AWS Secrets Manager/Parameter Store) issuing short-lived, rotated credentials - never hardcoded secrets or plaintext CI variables. Scan history with trufflehog/gitleaks (a "removed" key is still in git history) and rotate anything ever exposed.

### Why is mTLS not sufficient for service-to-service authorization?
mTLS proves *identity* (both sides authenticate), not *permission*. Treating "authenticated internal traffic" as "allowed to do anything" is the same authN-vs-authZ confusion as BOLA. Layer per-method, per-caller authorization policy on top of the verified certificate identity.

---

## 5. Active Directory

Full practitioner detail (enumeration, attack chains, tooling) is in
[network-infrastructure-security-testing.md](../testing/network-infrastructure-security-testing.md#6-active-directory);
red-team framing is in [red-team.md](red-team.md). This section is the interview
summary.

### What is Active Directory and AD DS?
AD is Microsoft's directory service - the central brain of a Windows domain that
authenticates/authorizes users, controls access to resources, applies policy, and
manages systems centrally. **AD DS** (Domain Services) is the core service,
hosted on Windows Server; its whole database lives in `NTDS.dit` on the domain
controller.

### The components?
- **Domain** - logical group of users/computers/servers/policies (`company.local`).
- **Domain Controller (DC)** - a server running AD DS; stores accounts, hashes,
  policies and does Kerberos auth. If the DC is down, users cannot log in.
- **Forest** - the top-level structure; multiple domains that trust each other
  (`company.local`, `india.company.local`, `europe.company.local`). **Tree** - a
  hierarchy of domains.
- **Organizational Unit (OU)** - container to organize objects (IT, Finance);
  GPOs apply here.
- **Objects** - everything in AD: users, groups, computers, printers, service
  accounts.
- **Groups** - security (assign permissions) vs distribution (email/Exchange).
- **GPOs** - rules applied to domains/OUs: disable USB, password policy, disable
  CMD/PowerShell, install software, firewall rules.

### Kerberos vs NTLM?
**Kerberos** is the default and more secure: a KDC issues a TGT (via AS-REQ/AS-REP)
which is exchanged for service tickets (TGS-REQ/TGS-REP). **NTLM** is older and
weaker, used when Kerberos fails, in workgroups, or for legacy apps. AD also
depends on **DNS**; Sites and Subnets control replication, and **SYSVOL** stores
GPOs and scripts.

### AD attacks?
The red-team TTPs against AD - Kerberoasting, AS-REP roasting,
Pass-the-Hash/Ticket, Golden/Silver ticket, DCSync, delegation/ACL abuse, lateral
movement and domain privilege escalation - are in [red-team.md](red-team.md).
This doc stays on the AD concepts, authentication and ports you get asked about
alongside networking.

### Ports that matter?
Kerberos 88, RPC 135, NetBIOS 139, LDAP 389, SMB 445, LDAPS 636 - each maps to an
enumeration or attack (Kerberoasting, DCOM RCE, null sessions, object enum,
EternalBlue/SMB relay, AD CS exploitation). Map attack paths with
**BloodHound**/**SharpHound**; common offensive tools are Mimikatz, Impacket,
CrackMapExec and PingCastle.
