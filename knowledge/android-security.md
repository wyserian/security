# Android Application Security - Interview Q&A

Android app pentesting. Maps to OWASP MASVS / MASTG and the OWASP Mobile Top 10 (2024). Remember: most "mobile" findings are really API findings surfaced through the app - test the backend with equal rigour (see [api-security.md](api-security.md)). The iOS counterpart is in [ios-security.md](ios-security.md).

---

## 1. OWASP Mobile Top 10 (2024)

The OWASP Mobile Top 10 and MASVS/MASTG apply to both Android and iOS; they are summarised here and referenced from the iOS notes.

| # | Category | Covers |
|---|---|---|
| M1 | Improper Credential Usage | hardcoded creds/API keys, insecure credential handling |
| M2 | Inadequate Supply Chain Security | vulnerable/malicious third-party SDKs, insecure build pipeline |
| M3 | Insecure Authentication/Authorization | client-side-only checks, broken token/session handling |
| M4 | Insufficient Input/Output Validation | unvalidated data from users, intents, deep links, backend |
| M5 | Insecure Communication | no/weak TLS, no cert pinning, cleartext traffic |
| M6 | Inadequate Privacy Controls | over-collection/exposure of PII |
| M7 | Insufficient Binary Protections | no obfuscation, debuggable release, weak anti-tamper |
| M8 | Security Misconfiguration | exported components without permission checks, bad manifest/WebView |
| M9 | Insecure Data Storage | tokens/PII in plaintext SharedPreferences/SQLite/logs |
| M10 | Insufficient Cryptography | hardcoded keys, weak algorithms (MD5/DES/ECB), broken custom crypto |

### What is OWASP MASVS / MASTG?
MASVS = Mobile Application Security Verification Standard; v2 groups controls into STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY. MASTG = the testing guide explaining how to test each control.

---

## 2. Android methodology

### Walk me through an Android pentest.
1. **Setup** - rooted device or emulator (Genymotion/AVD), Burp CA installed as a *system* cert, Frida server, ADB.
2. **Static** - decompile with JADX/apktool; read `AndroidManifest.xml` (exported components, `debuggable`, `allowBackup`, `usesCleartextTraffic`, permissions), hardcoded keys/URLs, weak crypto, logging. MobSF for a first pass.
3. **Dynamic** - intercept traffic, bypass SSL pinning and root detection, test the backend APIs like any web API.
4. **Data storage** - inspect `/data/data/<package>/` for shared_prefs, SQLite DBs, files, cache holding tokens/PII.
5. **Components** - test exported activities/services/receivers/providers via ADB or Drozer.
6. **Map to MASVS/MASTG**, then report.

### APK structure?
`AndroidManifest.xml`, `classes.dex` (Dalvik bytecode), `res/`, `assets/`, `lib/` (native `.so`), `META-INF/` (signature). apktool gives smali + resources; JADX gives readable Java.

### Key static-analysis artefacts?
Manifest (permissions, `exported`, `debuggable`, `allowBackup`), decompiled Java/smali (hardcoded secrets, crypto misuse, insecure logic), `shared_prefs` XML and SQLite DBs (plaintext data), native `.so` files for keys. Check build variants - debug builds leak far more (verbose logs, test endpoints, `debuggable=true`).

### How do you proxy Android traffic?
Set Burp as the device proxy and install Burp's CA. Since Android 7, apps don't trust user-added CAs by default, so install the cert as a *system* cert on a rooted device, or use a Frida/Magisk approach. Then observe decrypted API traffic including auth headers and hidden params.

---

## 3. Android - common findings

### What is the Android security model?
Each app runs in its own process with a unique Linux **UID**, sandboxed so it cannot read another app's private data (`/data/data/<pkg>/`) or memory by default. Apps interact only through declared, mediated channels - **permissions** (install-time/runtime, guarding sensitive APIs and data), **IPC** (intents, services, content providers, broadcasts), and signed APKs (same-signature apps can share a UID). The sandbox is kernel-enforced; most Android findings are an app weakening it - exporting a component, world-readable storage, a permissive WebView bridge, or `allowBackup`.

### How do you bypass SSL pinning?
Frida/Objection (`objection -g <app> explore` -> `android sslpinning disable`), universal Frida scripts hooking OkHttp `CertificatePinner`/TrustManager/WebView, or patch the APK (`network_security_config.xml` to trust user certs, rebuild with apktool, re-sign with apksigner). **Developer fix:** pin to a backup key too (survive rotation), combine with root/tamper detection, obfuscate pinning logic.

### How do you bypass root detection?
Objection `android root disable`, Frida hooks on checks like RootBeer / `su` lookups, Magisk DenyList/Zygisk to hide root, or patch the smali check and rebuild. **Developer fix:** layer multiple independent checks and back them with server-side signals (Play Integrity API) rather than client-only detection.

### Exported components - risk and test?
An exported activity can be launched by any app, skipping login: `adb shell am start -n com.app/.AdminActivity`. Exported content providers can leak data or allow SQLi: `adb shell content query --uri content://com.app.provider/users`. Drozer: `run app.package.attacksurface <pkg>`. **Fix:** `android:exported="false"` unless genuinely needed; otherwise enforce a `permission` and validate the calling package/signature.

### Insecure data storage examples?
Tokens/PII in SharedPreferences or SQLite in plaintext, data in logcat, sensitive data on external storage, backups enabled (`allowBackup=true`), keyboard cache, screenshots of sensitive screens. **Fix:** Android Keystore, `EncryptedSharedPreferences`, `FLAG_SECURE`, `allowBackup=false`, strip verbose logging from release.

### Insecure IPC beyond exported components?
Unprotected broadcast receivers accepting spoofed broadcasts, implicit-intent hijacking (a malicious app intercepts an implicit intent), intent redirection. **Fix:** explicit intents, `exported=false`, custom permissions, validate all IPC input.

### WebView issues?
`setJavaScriptEnabled(true)` with `addJavascriptInterface` exposing native methods to page JS, loading untrusted URLs, file access enabled, deep links loading attacker URLs. **Fix:** only `@JavascriptInterface`-annotated safe methods, disable file access, validate loaded URLs.

### Deep link / intent issues?
Deep links (`app://reset?token=`) that perform actions without validating the token/caller, intent redirection, unvalidated URLs loaded into a WebView. **Fix:** server-side validation of deep-link actions, don't trust link parameters for auth.

### Over-privileged permissions?
A utility app requesting `READ_CONTACTS`/`ACCESS_FINE_LOCATION`/`READ_SMS` with no functional need - flag as a least-privilege/privacy finding. **Fix:** request least privilege, scoped storage, foreground-only/one-time location.

### What is Frida and how does it work?
A dynamic instrumentation toolkit. A Frida server on the device injects into the app process; your JavaScript hooks functions at runtime to read arguments, change return values (e.g. make `isRooted()` return `false`), or neutralise checks.

### Tapjacking?
A transparent overlay tricks the user into tapping sensitive buttons. **Fix:** `setFilterTouchesWhenObscured(true)`, `FLAG_SECURE` where applicable.

### Activity / task hijacking?
Beyond exported activities, **task hijacking (StrandHogg)** abuses `taskAffinity`/`launchMode` so a malicious app inserts its own activity into the victim app's back-stack and shows a spoofed screen (e.g. a fake login) when the user opens the real app. **Activity spoofing** more broadly overlays or impersonates a legitimate screen to phish credentials. **Fix:** set `taskAffinity=""` (or a private affinity), choose `launchMode` carefully, be deliberate with `FLAG_ACTIVITY_NEW_TASK`, and target a patched SDK.

### Dynamic code loading?
Apps that load code at runtime - `DexClassLoader` on a downloaded DEX/JAR/APK, a native `.so` pulled from storage, or JavaScript injected into a WebView - are vulnerable when the loaded artefact is not integrity-checked. An attacker who can write to that location (world-writable/external storage, or a MITM over cleartext) swaps in malicious code that runs with the app's permissions. **Fix:** load only from internal storage or the signed APK, verify a signature/hash before loading, and never load code over cleartext.

### De-obfuscation & reverse engineering (raw SQL, logic)?
Decompiling the APK (JADX/apktool) and de-obfuscating it exposes hardcoded raw SQL queries, secrets, endpoints and business logic. Raw SQL built by string concatenation in the app or a content provider is both a disclosure and a local SQLi risk. **Fix:** obfuscate release builds (R8/ProGuard), keep secrets server-side, and parameterise queries even locally.

### App integrity & anti-tamper checks?
A missing integrity check lets a repackaged/patched APK (ads stripped, pinning disabled, cheats added) run undetected. **Fix:** verify the signing certificate at runtime, use the server-verified **Play Integrity API** rather than a client-only check, and combine it with root/tamper detection.

### Anti-analysis detection and why bypasses are findings (root, emulator, Frida, proxy, developer mode, OS version)
Apps often try to detect a testing environment - root/jailbreak, emulator/VM, Frida/instrumentation, a configured HTTP proxy, developer mode, or an outdated/insecure OS version - and refuse to run. These are defence-in-depth, not security boundaries, and each is bypassable: Objection/Frida hooks on the detection method, Magisk/Zygisk hiding root, patching the smali check and rebuilding, spoofing `Build` properties for emulator checks, or hiding the proxy. As a tester you bypass them to continue the assessment; as a finding, "root/emulator/Frida/proxy/developer-mode detection not configured" - or trivially bypassable, or install allowed on an end-of-life OS - is reported against **OWASP MASVS-RESILIENCE**. **Developer fix:** layer multiple independent checks, obfuscate them, and back them with a server-side signal (Play Integrity); never rely on client-side detection alone.

---

## 4. Android vs iOS - key differences for a tester
iOS apps are sandboxed more tightly and distributed only via the App Store (signed, encrypted binaries), so you usually need a jailbreak and to decrypt the IPA before static analysis. Android is more open (sideloading, rooting, readable DEX), and exported IPC components are a bigger attack surface. Storage targets differ: Keychain/plist/Core Data on iOS vs SharedPreferences/SQLite on Android. Full iOS detail is in [ios-security.md](ios-security.md).
