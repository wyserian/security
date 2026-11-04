# Android Application Security Testing

Full testing flow for Android apps - process, static/dynamic analysis, detection-bypass, tool setup, checklists and resources. Maps to OWASP MASVS/MASTG. Most "mobile" findings are really API findings surfaced through the app - test the backend with [api-security-testing.md](api-security-testing.md) and payloads in [payload-reference.md](payload-reference.md). Tool inventory in [tools-reference.md](tools-reference.md); iOS counterpart in [ios-security-testing.md](ios-security-testing.md). Use only on apps you own or are authorized to test.

---

# ANDROID PENTESTING

---

## 1. Reconnaissance & Information Gathering

### APK Basic Information
```bash
aapt dump badging app.apk
```
- Check: App Name, Package Name, Version Name/Code, Min/Target SDK, Permissions, Launch Activity

### Signing Certificate
```bash
keytool -printcert -jarfile app.apk
apksigner verify --verbose app.apk
```
- Debug certificate in use (risk: APK tampering)
- Production certificate validation

### Attack Surface Mapping
- Activities, Services, Broadcast Receivers, Content Providers
- Deep links, network endpoints, APIs, third-party SDKs
- Tools: `MobSF`, `apktool`, `jadx`, `androguard`

---

## 2. Static Analysis

### AndroidManifest.xml
```bash
apktool d app.apk
```

#### Exported Activities
- `android:exported="true"` - launch without auth
```bash
adb shell am start -n <package>/<activity>
```
- Access hidden functionality, admin screens, bypass authentication

#### Exported Services
```bash
adb shell am startservice -n <package>/<service>
```
- Start service externally, abuse service functionality

#### Exported Broadcast Receivers
```bash
adb shell am broadcast -a <ACTION_NAME>
```
- Trigger sensitive operations, bypass authentication

#### Exported Content Providers
```bash
adb shell content query --uri content://<package>.provider/
adb shell content insert --uri content://<package>.provider/ --bind column:s:value
adb shell content update --uri content://<package>.provider/ --bind column:s:value
```
- Unauthorized read/write, SQL injection via content provider URIs

#### Dangerous Flags
| Flag | Risk |
|------|------|
| `android:debuggable="true"` | Full app compromise via debugger |
| `android:allowBackup="true"` | Data extraction via `adb backup` |
| `android:usesCleartextTraffic="true"` | MITM possible |
| `android:exported="true"` (unprotected) | Unauthorized access |

```bash
# Extract backup
adb backup -apk -shared <package>
```

### Permission Analysis
- Identify dangerous permissions:
  - `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`
  - `READ_CONTACTS`, `READ_SMS`, `RECORD_AUDIO`
  - `CAMERA`, `ACCESS_FINE_LOCATION`, `READ_CALL_LOG`
- Verify necessity of each permission

### Hardcoded Secrets
- Decompile with `jadx` or `apktool`
- Search for: `password`, `token`, `secret`, `key`, `authorization`, `bearer`, `firebase`, `aws`
- Check: `strings.xml`, `BuildConfig`, `assets/`, `res/raw/`
- Types: API keys, bearer tokens, Firebase keys, AWS keys, JWT tokens, encryption keys

### Reverse Engineering Protections
- Check ProGuard/R8/DexGuard obfuscation enabled
- Missing obfuscation = easy source code recovery
- Tools: `jadx`, `apktool`, `BytecodeViewer`

---

## 3. Local Storage Testing
Base path: `/data/data/<package>/`

### Shared Preferences
```bash
adb shell cat /data/data/<package>/shared_prefs/<file>.xml
```
- Tokens stored in plaintext, credentials, sensitive data

### SQLite Databases
```bash
adb shell sqlite3 /data/data/<package>/databases/<db>.db
.tables
SELECT * FROM users;
```
- Plaintext credentials, sensitive user data, unencrypted PII

### Internal Storage
```bash
adb shell ls /data/data/<package>/files/
```
- Sensitive files, cached credentials, private keys

### External Storage
```bash
adb shell ls /sdcard/<package>/
```
- Sensitive data stored on public SD card
- Readable by any app with `READ_EXTERNAL_STORAGE`

### Cache Storage
```bash
adb shell ls /data/data/<package>/cache/
```
- Sensitive data cached (HTTP responses, images with PII)

---

## 4. Network Communication Testing

### Traffic Interception Setup
```bash
# Set proxy on device
adb shell settings put global http_proxy <ip>:<port>

# Install Burp CA certificate on device
adb push burp_cert.der /sdcard/
# Then install via Settings > Security > Install from storage
```
- Tools: `Burp Suite`, `mitmproxy`, `Charles Proxy`

### Insecure Communication
- HTTP used for sensitive data transmission
- Sensitive data (passwords, tokens, PII) in HTTP traffic
- Cleartext credentials in request bodies or headers

### Sensitive Data Exposure in Transit
- Passwords, tokens, session IDs, personal data in cleartext
- Authorization headers logged or leaked

### SSL Pinning Testing
- Check if SSL pinning is implemented
- Bypass using:
  - `Frida` with SSL unpinning scripts
  - `Objection`: `objection -g <package> explore` -> `android sslpinning disable`
  - `apk-mitm` for automated patching
  - Xposed + TrustMeAlready module

### Certificate Validation
- Accepts invalid/self-signed certificates
- Improper hostname verification
- `TrustAllCerts` implementation in code

---

## 5. Authentication Testing
- Biometric authentication bypass (Frida hook `FingerprintManager`, `BiometricPrompt`)
- Authentication state stored client-side (SharedPrefs, SQLite) - bypass by modifying storage
- Token not validated server-side after biometric success
- PIN/pattern stored insecurely

---

## 6. WebView Testing
- `setJavaScriptEnabled(true)` - XSS possible in WebView
- `addJavascriptInterface()` - JS-to-Java bridge exploitation (RCE risk pre-API 17)
- `setAllowFileAccess(true)` - local file theft via `file://` URIs
- `setAllowUniversalAccessFromFileURLs(true)` - cross-origin file access
- Load arbitrary URLs in WebView (open redirect inside app)
- XSS in WebView via JavaScript-enabled interface
- Deep link -> WebView URL injection

---

## 7. Deep Link Testing
```bash
# Check manifest for deep link handlers
grep -i "intent.action.VIEW" AndroidManifest.xml

# Test via ADB
adb shell am start -a android.intent.action.VIEW -d "app://target/path"
adb shell am start -a android.intent.action.VIEW -d "https://target.com/reset?token=xxx"
```
- Authentication bypass via deep link
- Access restricted activity/pages
- Parameter injection via deep link URL
- Host/path validation missing

---

## 8. Intent Security Testing
- Intent injection - malicious intent sent to exported activity/service/receiver
- Intent redirection - exported activity redirects to attacker-controlled component
- Sticky broadcasts - sensitive data in persistent broadcasts
- Implicit intent interception - sensitive data passed via unprotected implicit intent

---

## 9. Dynamic Analysis

### Frida / Objection
```bash
# Start Objection
objection -g <package> explore

# Common commands
android sslpinning disable
android root disable
android hooking list classes
android hooking watch class <ClassName>
android hooking watch method <ClassName>.<method> --dump-args --dump-return
```

### Runtime Checks
- Runtime manipulation of app state
- Token extraction from memory
- Bypass of root/emulator detection
- Method hooking and return value modification

### ADB Logcat Analysis
```bash
adb logcat | grep -i <package>
adb logcat *:E          # errors only
```
- Passwords, tokens, session IDs, sensitive data in logs
- Crash logs exposing internal paths, keys, or PII

---

## 10. Cryptography Testing
- Weak encryption algorithms: DES, 3DES, RC4, MD5 for security
- Hardcoded encryption keys in source code
- ECB mode in block ciphers (no IV, predictable patterns)
- Custom/home-grown cryptography
- Weak random: `java.util.Random` instead of `SecureRandom`
- IV reuse across encrypted blocks
- Insufficient key length (< 128-bit AES)

---

## 11. Runtime Protection Testing

### Root Detection
- Check if implemented
- Bypass:
  - `Frida` hook `RootBeer`, `SafetyNet`
  - `Magisk` with MagiskHide/Shamiko
  - `Objection`: `android root disable`

### Emulator Detection
- Check detection presence in code
- Bypass via: modifying build props, Frida hooks, custom emulator images

### Debugger Detection
- Check `android:debuggable` and `Debug.isDebuggerConnected()` calls
- Bypass via Frida hooks

### Frida Detection
- Check for Frida presence checks
- Bypass: use Frida gadget, custom Frida builds, obfuscated injection

### Code Tampering / Integrity Check
- Modify APK -> re-sign -> reinstall
- Check if tampering is detected (signature verification, checksum)
- Bypass: patch integrity check via smali/Frida

---

## 12. Miscellaneous Checks

### Clipboard Testing
- Sensitive data (passwords, tokens) copied to clipboard
- Other apps can read clipboard contents

### Screenshot Protection
- Check `FLAG_SECURE` is set on sensitive screens
- Test: take screenshot on sensitive screen -> should be blocked

### Firebase Security
```bash
# Test unauthenticated access
curl https://<project>.firebaseio.com/.json
curl https://<project>.firebaseio.com/users.json
```
- Firebase Realtime DB/Firestore with public read/write rules
- Unauthorized access to Firebase storage

### Third-Party Library Security
- Outdated dependencies with known CVEs
- Tools: `MobSF` dependency scan, `OWASP Dependency-Check`

### File System Security
- Path traversal via content provider or file operations
- Arbitrary file read/write via exposed providers

### Overlay / Tapjacking
- Tapjacking: malicious overlay captures taps on sensitive UI
- Check `filterTouchesWhenObscured` flag on sensitive views
- `setFilterTouchesWhenObscured(true)` required

### Backup Testing
```bash
adb backup -apk -shared <package>
java -jar abe.jar unpack backup.ab backup.tar
tar -xvf backup.tar
```
- Sensitive data extracted from backup

---

## 13. Quick Reference: Tools

| Category | Tools |
|----------|-------|
| Static Analysis | `MobSF`, `jadx`, `apktool`, `BytecodeViewer`, `androguard` |
| Dynamic Analysis | `Frida`, `Objection`, `Drozer` |
| Traffic Interception | `Burp Suite`, `mitmproxy`, `Charles Proxy` |
| ADB | `adb`, Android Debug Bridge |
| SSL Bypass | `Frida`, `Objection`, `apk-mitm`, `TrustMeAlready` |
| Root Tools | `Magisk`, `Shamiko`, `MagiskHide` |
| Crypto Analysis | `jadx` + manual review |
| Firebase | `Firebase Scanner`, manual curl |
| Backup | `adb backup`, `abe.jar` |
| Repackaging | `apktool` + `apksigner` |
| Signing | `apksigner`, `jarsigner` |
| Automation | `MobSF` (full pipeline) |

(Full inventory with URLs in [tools-reference.md](tools-reference.md).)

---

## 14. Detection & Bypass Mechanisms (deep dive)

Modern apps (banking, UPI, streaming, DRM, exam) layer client-side defences. These are defence-in-depth, not security boundaries - each is bypassable, and "not configured / trivially bypassable" is itself a finding (OWASP MASVS-RESILIENCE). Bypassing often requires defeating **several layers together**.

### 14.1 SafetyNet / Play Integrity API
- Google service checking device integrity, bootloader state, system modifications; used by banking/payments/streaming/DRM. Rooted/unlocked devices often fail.
- Checks: bootloader state, verified boot, device integrity, CTS profile.
- Bypass concepts: systemless root hiding (MagiskHide/Zygisk), hardware-backed attestation evasion, Play Integrity spoofing (Universal SafetyNet Fix, Play Integrity Fix). Google tightening it server-side -> hardware-backed attestation (TEE/TrustZone) is much harder.

### 14.2 Root detection
- **How apps detect:** `su` binary, unlocked bootloader, modified/missing Verified Boot keys, Magisk files / root-manager packages, writable system partitions, debuggable build tags, hooked processes (Xposed/Zygisk), busybox, test-keys, mount RW, frida-server.
- **Code review (JADX) keywords:** `root, isRoot, checkRoot, superuser, su, RootBeer`; paths `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/vendor/bin/su`, `/system/app/Superuser.apk`, `/system/app/SuperSU.apk`, `/system/app/Magisk.apk`; command checks `which su`, `su -c`, `busybox`, `id`, `whoami`; file-existence `new File("/system/xbin/su").exists()`; packages `eu.chainfire.supersu`, `com.topjohnwu.magisk`, `com.noshufou.android.su`, `com.koushikdutta.superuser`; libs `com.scottyab.rootbeer`; SafetyNet/Play Integrity `ctsProfileMatch`, `basicIntegrity`, `MEETS_DEVICE_INTEGRITY`.
- **Bypass:** Magisk Zygisk + DenyList + **Shamiko**; file/path hiding (MagiskHide Props Config); Universal SafetyNet Fix / custom props (fingerprint spoof); APK patching (smali edits, Frida hooks); LSPosed/Xposed targeted modules (RootCloak). Objection `android root disable`; Frida hooks on RootBeer/`su` lookups.

### 14.3 Bootloader-unlock detection
- Detected via OEM flags `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.boot.vbmeta.device_state`; dm-verity state (orange/yellow/red boot); AVB integrity; Play Integrity bootloader-unlock reporting.
- Bypass: Magisk property spoofing (MagiskHide Props Config -> `ro.boot.flash.locked=1`, `vbmeta.device_state=locked`, `verifiedbootstate=green`); Universal SafetyNet Fix + Play Integrity Fix; Zygisk + DenyList/Shamiko; hook `KeyAttestation`/SafetyNet via LSPosed/Frida; real/fake relock (risky). Hardware-backed key attestation is much harder.

### 14.4 Developer-options / USB-debug detection
- Detected via `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`, `ADB_ENABLED`, `Settings.Secure.ALLOW_MOCK_LOCATION`, or a running ADB daemon.
- Bypass: hook `Settings.Global.getInt()` to return 0 (LSPosed/Frida); Magisk property spoofing; temporarily disable Developer Options; hook the app's `isDevelopmentSettingsEnabled()`.

### 14.5 SSL pinning (deep)
- App trusts only a pinned cert/public key, not the whole CA store - so installing Burp's CA lets the browser work but app traffic fails.
- **Types:** cert pinning (hardcoded cert), public-key pinning (key hash), Network Security Config (XML), library-based (OkHttp `CertificatePinner`, TrustKit, TrustManager), native (OpenSSL/BoringSSL), hardware-backed keystore.
- **Where found:** `network_security_config.xml`, `OkHttpClient`, `TrustManager`, `CertificatePinner`, native libs.
- **Bypass:** Frida hooks (`checkServerTrusted`, OkHttp `CertificatePinner`) -> always valid; Objection `android sslpinning disable`; Xposed/LSPosed **JustTrustMe** / SSLUnpinning; Magisk **TrustMeAlready** / Universal SSL Unpinning; manual smali/native patching (remove pinning, recompile, re-sign); install custom CA as system cert; override `network_security_config.xml`. Native (C/C++ OpenSSL) + obfuscation + combined root detection make it harder.

### 14.6 Anti-debugging (debugger checks)
- Java: `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`; system props `ro.debuggable`/`ro.secure`; native `ptrace()` / `/proc/self/status` `TracerPid` (non-zero = debugged); timing checks.
- Bypass: Frida hook `Debug.isDebuggerConnected` -> false; Objection; Xposed/LSPosed; kernel-level Magisk modules; hook libc `ptrace`/`open`/`read` (Interceptor.attach) and force `TracerPid: 0`; static patch (`const/4 v0, 0x0`), rebuild, re-sign.

### 14.7 Emulator / VM detection
- Checks: build props (generic/sdk), QEMU drivers, missing IMEI/sensors.
- Bypass: property spoofing, sensor injection, device-fingerprint cloning.

### 14.8 Anti-Frida / anti-hooking
- Detection: frida-server ports, memory scans, loaded-library checks, thread-name inspection.
- Bypass: rename/relocate Frida, inline hooking, early-process injection, kernel-level hooking, Frida gadget / custom builds.

### 14.9 Integrity & tamper detection
- Checks: APK signature, DEX checksum, CRC/hash, code-section integrity.
- Bypass: patch verification logic, hook integrity functions, modify return values.

### 14.10 Obfuscation & packing
- Techniques: ProGuard/R8, DEX encryption, dynamic class loading, custom packers.
- Bypass: runtime dumping, memory analysis, decryption hook points.

### 14.11 PAIRIP (`libpairipcore.so`)
- Native (`/lib/arm64-v8a/libpairipcore.so`) commercial app-protection (Pair IP). Validates Play Store install + app signature, blocks Frida/GDB, uses an obfuscated VM. Performs `ro.kernel.qemu` checks, build-fingerprint checks, emulator-artifact checks, Frida detection, ptrace/debugger detection, SELinux verification - at the native layer, so Java-only bypasses fail. Public bypasses: LSPosed **pairipfix**, Frida hooks on `libpairipcore.so`, VM-stripping guides.

### 14.12 Hooking / bypass frameworks
- **Xposed** - runtime Java-method hooking without modifying APKs (root + installer; legacy on modern Android).
- **Riru** - Magisk module injecting into zygote so Xposed-style frameworks run on modern Android.
- **LSPosed** - modern Xposed via Riru/Zygisk; per-app scope; modules like JustTrustMe, RootCloak, debugger-bypass.
- **Frida** - dynamic instrumentation (root or gadget); custom JS hooks on Java+native; works on obfuscated apps.
- Stack: Magisk (root) -> Riru (zygote injection) -> LSPosed/Xposed (hook) -> modules (JustTrustMe/SSLUnpinning/RootCloak).

### 14.13 Rooting internals & Magisk
- Android = Linux; root = UID 0; apps are sandboxed per-UID by Zygote + SELinux; `su` binary is absent by default. Rooting installs `su`; a superuser manager (Magisk/SuperSU) gates requests. **Systemless root (Magisk)** patches the boot image (injects at boot via zygote) instead of `/system` - survives Verified Boot, easy OTA/uninstall. Root lets apps mount partitions RW, change SELinux state, hook system services. Magisk features: Zygisk, DenyList, modules, MagiskHide -> Zygisk. Install: patch `boot.img` in Magisk app -> `fastboot flash boot_a magisk_patched_boot.img` -> reboot.
- Useful modules: InitRcHider, Always Trust User Certificates, MagiskHide Props Config, Play Integrity Fix, Shamiko, LSPosed, Xposed, KernelSU (kernel-based root alternative).

### 14.14 Why mobile apps are a distinct attack surface
Apps run in untrusted, user-controlled environments; large runtime attack surface via instrumentation/debugging; hardcoded secrets/APIs extractable; millions of distributed instances; easy reverse engineering of APKs; weak/missing root-jailbreak/tamper/runtime protections; secure backends still reachable through weak app implementations; users on compromised devices / malicious overlays.

---

## 15. Tool Setup & Commands

### Environment
```bash
pip install frida-tools objection
sudo apt install adb apktool default-jdk
# Jadx: github.com/skylot/jadx/releases ; MobSF via docker (below)
# MPT toolkit bundles MobSF, Objection, Jadx, apktool, Frida, ADB
```
### MobSF
```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload APK -> automated static + dynamic report
```
### ADB / static
```bash
adb devices ; adb shell pm list packages | grep <kw> ; adb shell pm path <pkg> ; adb pull <apk>
adb shell run-as <pkg> ls ; adb logcat | pidcat <pkg>
adb shell dumpsys package <pkg> | grep -i exported
jadx-gui app.apk ; apktool d app.apk -o out/ ; dex2jar app.apk && jd-gui app.jar
adb shell am start -n com.package.app/com.package.app.MainActivity   # launch activity
```
### Frida server
```bash
adb shell getprop ro.product.cpu.abi            # architecture
adb push frida-server /data/local/tmp/
adb shell "su -c chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"   # or the versioned binary name
frida-ps -U                                     # verify
frida -U -f com.pkg -l root_bypass.js --no-pause   # launch + hook
frida -U -n com.pkg -l ssl_bypass.js               # attach to running
pkill -f frida                                  # if already running
```
### Objection / Drozer
```bash
objection -g <pkg> explore
#   android root disable | android sslpinning disable
#   android hooking list activities | android intent launch_activity <Activity>
adb forward tcp:31415 tcp:31415 ; drozer console connect
run app.package.attacksurface <pkg> ; run app.activity.info -a <pkg> ; run app.provider.info -a <pkg>
run app.activity.start --component <pkg> <Activity>
```
### Proxy + Burp CA on emulator (MEmu/AVD)
```
# Burp: Proxy -> listener on 8080, all interfaces. Device on same Wi-Fi.
# Emulator: Settings -> WiFi -> Modify -> Advanced -> Proxy Manual -> <ip>:8080
# CA: browse http://burp -> download cacert.der -> rename .cer -> 
#     Settings -> Security -> Encryption & credentials -> Install certificate -> CA
# Android 7+ ignores user CAs -> install as *system* cert (root) or Frida unpinning
```
### Frida snippets
```js
// trace a class method
Java.perform(function(){ var C=Java.use("com.target.Class");
  C.method.implementation=function(a){ console.log("called: "+a); return this.method(a);};});
// list modules / hook native
Process.enumerateModules().forEach(m=>console.log(m.name,m.base));
Interceptor.attach(Module.findExportByName(null,"strcmp"),{onEnter:a=>console.log(a[0].readCString(),a[1].readCString())});
```
Universal scripts: codeshare.frida.re (e.g. `@pcipolloni/universal-android-ssl-pinning-bypass-with-frida`). `intrascan` injects Nuclei templates from inside the app when pinning blocks an external proxy.

---

## 16. Assessment Workflow & Checklists (Mobile SOP)

**Workflow:** Scope & setup (authorization, targets, build, test accounts, device/emulator, permitted techniques) -> Initial automated review (MobSF; treat as leads) -> Static analysis (package, decompiled code, manifest/metadata, endpoints, config, dependencies) -> Traffic analysis (Burp/ZAP/mitmproxy; verify proxy + cert; document traffic you cannot see) -> Runtime analysis (Frida/Objection/RMS where permitted) -> Security-control validation (pinning, root/jailbreak detection, exported components, logging, local storage, networking trust) -> Finding validation (reproduce; separate confirmed from tool output) -> Reporting & closure (impact, remediation, limitations; retest in scope).

**Pre-assessment checklist:**
- [ ] written authorization + scope
- [ ] package IDs listed
- [ ] platform + app version/build + environment recorded
- [ ] device/emulator availability; root/jailbreak permitted?
- [ ] proxy/static/runtime tools selected
- [ ] tool versions recorded
- [ ] evidence/reporting process ready.

**Common-findings checklist:**
- [ ] hardcoded secrets/API keys (jadx grep, strings, MobSF)
- [ ] exported activities/services/providers (Drozer)
- [ ] insecure storage (SharedPrefs/SQLite/plist/keychain)
- [ ] weak crypto / ECB / hardcoded IV
- [ ] SSL pinning absent/bypassable
- [ ] root/jailbreak detection bypassable
- [ ] backup enabled (allowBackup)
- [ ] debuggable build
- [ ] deep link / URL scheme hijack
- [ ] WebView JS bridge exposure
- [ ] log leakage (logcat)
- [ ] biometric/auth-flow bypass.

**Reporting/closure checklist:**
- [ ] app/platform/build, environment, date, tools+versions, scope limits
- [ ] per finding: reproducible steps, evidence, affected component, prerequisites, impact, remediation
- [ ] separate confirmed vs suspected vs tool alerts vs library risk
- [ ] record untested areas/blockers (device, root, un-interceptable traffic)
- [ ] confirm testing stayed in scope
- [ ] deliver via agreed process; retest only when authorized.

For each test record: app version, Android version, device/emulator, preconditions, exact repro steps, request/response or logs (redact secrets/PII), impact, affected component, remediation, and the MASTG/MASVS reference.

---

## 17. Learning Resources

**Practice:** InsecureBankv2 (`github.com/dineshshetty/Android-InsecureBankv2`), 8kSec Battlegrounds (`8ksec.io`), Mobile Hacking Lab (`mobilehackinglab.com`), Bugcrowd Mobile Hacking Resource Kit, RingSafe Academy (`ringsafe.in`).
**Official:** OWASP MASTG (`mas.owasp.org/MASTG/`), MASVS (`mas.owasp.org/MASVS/`), Mobile App Security project (`owasp.org/www-project-mobile-app-security/`).
**Guided reading:** Android Pentest Runbook (ADB/Frida/Objection), SSL-pinning bypass with Frida+Burp, Getting Started with Android AppSec, Practical Mobile Traffic Interception, tracing attacker-controlled data through apps, complete practical Android pentesting guide (Medium - verify currency).
**Suggested order:** APK basics/manifest/JADX/apktool -> ADB/logcat/app-data/SharedPrefs/SQLite -> Burp proxy + API traffic -> Frida/Objection -> SSL-pinning & root-detection (authorized lab) -> exported components -> deep links/intents/WebView -> auth/authz/business logic -> map to MASTG/MASVS + report.
