# iOS Application Security Testing

Full testing flow for iOS apps - process, static/dynamic analysis, storage, network, bypass, checklists, tools and resources. Maps to OWASP MASVS/MASTG. Same standard as Android ([android-security-testing.md](android-security-testing.md)); most "mobile" findings are really API findings surfaced through the app - test the backend with [api-security-testing.md](api-security-testing.md) and payloads in [payload-reference.md](payload-reference.md). Tool inventory in [tools-reference.md](tools-reference.md). Use only on apps/devices you own or are authorized to test.

> Many iOS dynamic/binary-dumping tools require a **jailbroken** device (Clutch, Cycript, bfinject, keychaindumper); non-jailbroken testing uses a Frida gadget injected into a re-signed app. Jailbreak steps vary hugely by device + iOS version - check the tool's official compatibility before proceeding.

---

## 1. iOS methodology (workflow)

1. **Scope & setup** - authorization, app build, test accounts, device/jailbreak state, permitted techniques. Jailbroken device (checkra1n/palera1n/Dopamine) with Frida, Objection, SSH (default `alpine/alpine`), or non-jailbroken via Frida-gadget injection. A Mac + Xcode helps.
2. **Acquire & decrypt** - App Store binaries are FairPlay-encrypted; dump a decrypted IPA with **frida-ios-dump** (or bagbak/Clutch/Dumpdecrypted) before static analysis.
3. **Static** - `Info.plist` (ATS, URL schemes, `UIFileSharingEnabled`), `class-dump` / Hopper / Ghidra for the Obj-C/Swift interface, `otool -L`/`-h`, hardcoded secrets (`strings`), entitlements (`codesign -d --entitlements :-`). MobSF for a first pass.
4. **Traffic** - Burp/ZAP/mitmproxy; install + **fully trust** the CA (Settings -> General -> VPN & Device Management -> profile, then Settings -> About -> Certificate Trust Settings -> enable). Bypass pinning first if needed.
5. **Storage** - Keychain, `NSUserDefaults`, plist, SQLite, Core Data, caches, logs, backups under the app sandbox.
6. **Dynamic/runtime** - Frida/Objection/Cycript/bfinject; bypass pinning and jailbreak detection; inspect runtime.
7. **Validate & report** - reproduce, separate confirmed from tool output, map to MASVS/MASTG, report with impact + remediation; retest in scope.

### IPA structure
A ZIP with `Payload/<App>.app/` containing the Mach-O executable, `Info.plist`, resources, embedded provisioning profile and `_CodeSignature`. On App Store builds the Mach-O is encrypted until dumped from memory on a jailbroken device.

---

## 2. Static analysis
```bash
frida-ios-dump -u <bundle_id>          # decrypt + pull IPA (jailbroken)
bagbak <bundle_id>                     # modern decryption
clutch -d <bundle_id>                  # jailbroken decryption
class-dump app_binary > headers.txt    # Obj-C runtime interface
otool -L app_binary                    # linked libraries
otool -h app_binary                    # Mach-O header
hopper / r2 / ghidra app_binary        # disassembly
plutil -p Info.plist                   # ATS, URL schemes
codesign -d --entitlements :- app_binary
```
- Hunt hardcoded secrets/keys/endpoints (`strings`, decompiled Swift/Obj-C).
- `Info.plist`: ATS exceptions (`NSAllowsArbitraryLoads`), custom URL schemes, `UIFileSharingEnabled`.
- Review bundled resources, config, third-party frameworks.

---

## 3. iOS - common findings

### 3.1 SSL pinning bypass
Objection `ios sslpinning disable`; Frida hooks on `SecTrustEvaluate`/`NSURLSession`/AFNetworking/TrustKit; **SSL Kill Switch 2** on a jailbroken device. **Fix:** pin a backup key, combine with jailbreak/tamper detection, don't rely on pinning alone.

### 3.2 Jailbreak-detection bypass
Objection `ios jailbreak disable`; Frida hooks on file-existence checks (`/Applications/Cydia.app`, `/bin/bash`), `fork()`/`canOpenURL:` probes, sandbox-write tests; Liberty/Shadow/**Xcon**/**tsProtector** tweaks. **Fix:** multiple independent checks, obfuscation, server-side signal (DeviceCheck/App Attest).

### 3.3 Insecure data storage
Tokens/PII in `NSUserDefaults` (plaintext plist); unprotected Keychain items (weak accessibility class, e.g. `kSecAttrAccessibleAlways`); plaintext SQLite/Core Data/Realm; secrets in caches or in an unencrypted backup. Extract from the sandbox (`/var/mobile/Containers/Data/Application/<UUID>/`) or `/var/Keychains/keychain-2.db` (keychaindumper). **Fix:** Keychain with `WhenUnlockedThisDeviceOnly`, Data Protection file classes, nothing sensitive in `NSUserDefaults`.

### 3.4 ATS / transport security
`Info.plist` ATS should force TLS; flag `NSAllowsArbitraryLoads` / per-domain exceptions permitting cleartext or weak TLS. **Fix:** remove exceptions, require TLS 1.2+.

### 3.5 URL scheme & Universal Link issues
Custom schemes (`myapp://`) can be registered by other apps -> hijackable if they perform actions or pass secrets; Universal Links are safer but must validate the inbound URL/caller. **Fix:** server-verified `apple-app-site-association`, validate every parameter, never trust a scheme for auth.

### 3.6 Inter-app / IPC & pasteboard
Insecure handling of data from URL schemes, share/activity extensions, app groups, and the **pasteboard** (general pasteboard leaks copied secrets to other apps). **Fix:** validate inbound data, scope app-group storage, keep secrets off the general pasteboard.

### 3.7 Screenshot / backgrounding leakage
iOS snapshots the screen on backgrounding (app switcher) -> sensitive screen cached to disk. **Fix:** blank/obscure sensitive views in `applicationDidEnterBackground`.

### 3.8 Binary protections
Missing PIE/ASLR, stack canaries, anti-debugging (`ptrace(PT_DENY_ATTACH)`), no obfuscation -> easy reversing/tampering. **Fix:** compiler mitigations, anti-debug + jailbreak/tamper detection, obfuscation (defence-in-depth).

### 3.9 Keychain / biometric bypass
Keychain items gated by Face ID/Touch ID can be reached if access-control flags are weak or the biometric gate is UI-only. **Fix:** `SecAccessControl` (`.biometryCurrentSet`/`.userPresence`) so key material itself is gated.

### 3.10 WebView / native bridges
`WKWebView`/`UIWebView` with JS enabled, untrusted URL loading, or an exposed native bridge -> injection. Validate loaded URLs and bridge inputs.

---

## 4. Dynamic / runtime & network
```bash
cycript -p <pid>                       # Obj-C runtime exploration
bfinject --lc <pid>                    # load dylib into running app
objection -g <bundle_id> explore
#   ios sslpinning disable | ios jailbreak disable | ios keychain dump
frida -U -f <bundle_id> -l ios-ssl-bypass.js
ssh root@<device_ip>                   # app data + keychain (jailbroken)
```
Proxy: Burp/ZAP on 8080; iOS WiFi -> HTTP Proxy -> Manual; install **and trust** the CA profile. `mitmproxy -p 8080`, `mallory` for mobile MITM. Frida native-hook snippet (`Interceptor.attach` on `strcmp`/socket APIs) works the same as on Android - see [android-security-testing.md](android-security-testing.md) section 15.

---

## 5. Library security review (iOS)
- **Alamofire** (networking) - not inherently vulnerable, but disabling cert validation / insecure custom `ServerTrustPolicy` enables MITM; proper pinning required.
- **SDWebImage** (image loading) - relies on libjpeg/libpng/WebP codecs; malicious images or "pixel bombs" can cause RCE/DoS via those codecs; keep deps patched.
- **CocoaLumberjack** (logging) - sensitive data in local/remote log files; path traversal if log paths are built from unsanitized input; verbose production logging is common.
- **Realm / Core Data** (databases) - extractable from the filesystem (jailbroken/backups) if stored unencrypted; risk is configuration-based.
- General iOS libs: exploitation is usually driven by developer **misconfiguration** (no pinning, unencrypted DB) rather than a library CVE.

---

## 6. Checklists
**Pre-assessment:**
- [ ] written authorization + scope
- [ ] bundle IDs listed
- [ ] app version/build + iOS version + device model
- [ ] jailbroken? which tooling versions
- [ ] proxy/static/runtime tools selected
- [ ] evidence/reporting process ready

**Common findings:**
- [ ] hardcoded secrets/keys
- [ ] insecure storage (Keychain flags, NSUserDefaults, SQLite/Realm/Core Data)
- [ ] SSL pinning absent/bypassable
- [ ] jailbreak detection bypassable
- [ ] ATS cleartext exceptions
- [ ] URL-scheme/Universal-Link abuse
- [ ] pasteboard/IPC leakage
- [ ] backgrounding snapshot leak
- [ ] weak binary protections / anti-debug
- [ ] biometric/Keychain bypass
- [ ] log leakage (oslog)
- [ ] WebView/native-bridge exposure

**Reporting:** app version/build, iOS version, device, jailbreak state + tool versions, preconditions, exact repro steps, sanitized logs/screenshots/requests, impact, affected component, remediation, and the MASTG/MASVS reference.

---

## 7. Tools (iOS)
Decryption/dump: **frida-ios-dump**, bagbak, Clutch, Dumpdecrypted. Analysis: **class-dump**, otool, Hopper/radare2/Ghidra, `plutil`, `codesign`. Runtime/bypass: **Frida**, **Objection**, Cycript, bfinject, idb, Passionfruit, **SSL Kill Switch 2**, Xcon/tsProtector, keychaindumper. Device/JB: **libimobiledevice**, ios-deploy, Xcode/Simulator, Sileo; jailbreaks **palera1n**/**Dopamine**/**checkra1n**; sideloading **Sideloadly**/**AltStore** (sideloading != jailbreak). Cross-platform: MobSF, Burp/ZAP/mitmproxy, Wireshark. (Full inventory + URLs in [tools-reference.md](tools-reference.md).)

---

## 8. Android vs iOS - key differences for a tester
iOS is sandboxed more tightly and distributed only via the App Store (signed, encrypted binaries) -> usually need a jailbreak and to decrypt the IPA before static analysis. Android is more open (sideloading, rooting, readable DEX) with exported IPC components as a bigger attack surface. Storage targets differ: Keychain/plist/Core Data (iOS) vs SharedPreferences/SQLite (Android).

---

## 9. Learning resources
Official: OWASP **MASTG** (`mas.owasp.org/MASTG/`) - techniques (`/techniques/index.html`) and tests (`/tests/`), **MASVS** (`mas.owasp.org/MASVS/`), MASTG tools list (`/MASTG/tools/`), Mobile App Security project. Guided reading: "Building an iOS Application Security Testing Lab" and the Medium iOS-pentesting search (verify currency). Tools to learn first: Frida, Burp, MobSF.
**Suggested order:** iOS architecture/sandbox/IPA/Info.plist -> static analysis of binaries/resources -> storage (Keychain/plist/SQLite/caches/logs/backups) -> network + TLS review -> Frida + Obj-C/Swift runtime -> URL schemes/universal links/extensions/pasteboard -> WebView & native bridges -> auth/authz/biometrics/business logic -> jailbreak detection/anti-debug/anti-reversing -> map to MASTG/MASVS + report.
