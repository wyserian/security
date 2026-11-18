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
Multiple techniques - the pin check is client-side, so on a rooted/instrumented device you control the runtime:
- **Frida / Objection** - `objection -g <app> explore` -> `android sslpinning disable`, or universal Frida scripts hooking OkHttp `CertificatePinner` / `checkServerTrusted` / `TrustManager` / WebView to always return valid.
- **Magisk modules** - **TrustMeAlready**, **Universal SSL Unpinning** (systemless, no app repack).
- **Xposed / LSPosed modules** - **JustTrustMe**, **SSLUnpinning** (hook the pinning APIs framework-wide). Stack: Magisk -> Riru/Zygisk -> LSPosed -> module.
- **Patch the APK** - edit `network_security_config.xml` to trust user CAs (or remove pinning), rebuild with apktool, re-sign with apksigner; or `apk-mitm` for automated patching.
- **Install the Burp/ZAP CA as a system cert** (rooted) so user-added-CA restrictions don't apply.
- **Native pinning** (C/C++ in a `.so`, e.g. OpenSSL/BoringSSL) - hook the native verify function (`ssl_verify_peer_cert`) with Frida by pattern.
- **Flutter** - standard hooks/proxy fail; use **reFlutter** or hook `ssl_verify_peer_cert` in `libflutter.so` (see the Flutter entry).

**Developer fix:** pin to a backup key too (survive rotation), combine with root/tamper detection and server-side attestation (Play Integrity), and obfuscate pinning logic - pinning alone on an unhardened app is trivially removed.

### How do you bypass root detection?
Objection `android root disable`, Frida hooks on checks like RootBeer / `su` lookups, Magisk DenyList/Zygisk to hide root, or patch the smali check and rebuild. **Developer fix:** layer multiple independent checks and back them with server-side signals (Play Integrity API) rather than client-only detection.

### Exported components - risk and test?
An exported activity can be launched by any app, skipping login: `adb shell am start -n com.app/.AdminActivity`. Exported content providers can leak data or allow SQLi: `adb shell content query --uri content://com.app.provider/users`. Drozer: `run app.package.attacksurface <pkg>`. **Fix:** `android:exported="false"` unless genuinely needed; otherwise enforce a `permission` and validate the calling package/signature.

### Insecure data storage examples?
Tokens/PII in SharedPreferences or SQLite in plaintext, data in logcat, sensitive data on external storage, backups enabled (`allowBackup=true`), keyboard cache, screenshots of sensitive screens. **Fix:** Android Keystore, `EncryptedSharedPreferences`, `FLAG_SECURE`, `allowBackup=false`, strip verbose logging from release.

### Insecure IPC beyond exported components?
Unprotected broadcast receivers accepting spoofed broadcasts, implicit-intent hijacking (a malicious app intercepts an implicit intent), intent redirection. **Fix:** explicit intents, `exported=false`, custom permissions, validate all IPC input.

### WebView issues?
**What.** An embedded browser component rendering web content inside the app; risky when JavaScript is enabled with attacker-influenced content.

**Vulnerabilities.**
- `setJavaScriptEnabled(true)` + untrusted content/params -> **XSS inside the app's WebView**.
- `addJavascriptInterface` exposes a native Java object to page JS -> JS can call native methods (**RCE-like**); catastrophic pre-API 17 (reflection -> `Runtime.exec`), still dangerous after if sensitive methods are exposed, and the bridge is callable from any loaded origin without a check.
- File access (`setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs`) -> a malicious page reads local files (`file:///data/data/<pkg>/...`) and steals tokens/DBs - the WebView-to-local-file-theft chain.
- `onReceivedSslError` calling `handler.proceed()` -> certificate validation is disabled -> **MITM**.
- Loading URLs over HTTP, or a deep-link `url` param loaded straight into the WebView -> attacker-controlled page / open redirect.

**Fix.** Disable JS if unneeded; expose only `@JavascriptInterface`-annotated safe methods and check the calling origin; disable the file-access flags; never call `handler.proceed()` on SSL errors; and allow-list loadable URLs.

### Deep link / App Link exploitation
**What they are.** URIs that open a specific screen in the app. Three kinds: **custom scheme** deep links (`kotak://transfer?...`) which are **unverified** - any app can register the same scheme; **App Links** (`https://` links) **verified** via an **`assetlinks.json`** hosted on the domain (secure if configured right); and **deferred** deep links that route after install.

**Vulnerabilities.**
- Unauthenticated sensitive actions - a deep link jumps straight to a transfer / add-payee / change-settings screen, skipping the auth flow.
- Parameter injection into a WebView - `kotak://open?url=https://evil.com` loads an attacker URL in a WebView -> XSS / phishing / credential theft (worse if `addJavascriptInterface` is exposed).
- Open redirect - the deep-link param is used directly as a redirect target.
- Scheme hijacking - because custom schemes aren't verified, a malicious app registers the same scheme and intercepts the link and its data (OAuth codes, tokens).
- Internal request / SSRF-like - a param flows into a server-side or internal request.
- Account takeover - a magic-link / password-reset flow handled by an insecure deep link.

**How you test it.** Enumerate handlers from the manifest (`<intent-filter>` with `android:scheme`/`android:host`, `android:autoVerify`), then trigger with `adb shell am start -W -a android.intent.action.VIEW -d "kotak://transfer?to=attacker&amt=10000"` and observe whether the action executes without authentication.

**Fix.**
- Require authentication before acting on a deep link.
- Validate/allow-list every parameter, especially any URL.
- Use **verified App Links (`assetlinks.json`)** rather than raw custom schemes for anything sensitive.
- Never pass deep-link data into a WebView or a redirect unchecked.

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
A missing integrity check lets a repackaged/patched APK (ads stripped, pinning disabled, cheats added) run undetected. **Fix:** verify the signing certificate at runtime, use the server-verified **Play Integrity API** rather than a client-only check, and combine it with root/tamper detection. Google's **PairIP** is an increasingly common app-integrity/anti-tamper layer (encrypts/obfuscates and validates the APK at runtime); as a tester you may need to defeat it to instrument the app (tools like `gpairip-bypass`), and like all client-side protection it is a hardening measure, not a trust boundary.

### Anti-analysis detection and why bypasses are findings (root, emulator, Frida, proxy, developer mode, OS version)
Apps often try to detect a testing environment - root/jailbreak, emulator/VM, Frida/instrumentation, a configured HTTP proxy, developer mode, or an outdated/insecure OS version - and refuse to run. These are defence-in-depth, not security boundaries, and each is bypassable: Objection/Frida hooks on the detection method, Magisk/Zygisk hiding root, patching the smali check and rebuilding, spoofing `Build` properties for emulator checks, or hiding the proxy. As a tester you bypass them to continue the assessment; as a finding, "root/emulator/Frida/proxy/developer-mode detection not configured" - or trivially bypassable, or install allowed on an end-of-life OS - is reported against **OWASP MASVS-RESILIENCE**. **Developer fix:** layer multiple independent checks, obfuscate them, and back them with a server-side signal (Play Integrity); never rely on client-side detection alone.

---

## 4. Android platform internals & tooling

### AndroidManifest.xml security misconfigurations
1. **`android:debuggable="true"`** - app is debuggable in production; an attacker can attach a debugger (jdb), run code in the app context, read memory, dump data. **Fix:** `debuggable="false"` (release builds default to false); never ship debug builds.
2. **`android:allowBackup="true"`** - app data extractable via `adb backup` **without root**, exposing tokens, databases, SharedPreferences, PII. **Fix:** `allowBackup="false"`, or a strict `fullBackupContent`/backup rules excluding sensitive data.
3. **Exported components (`android:exported="true"`)** - activities/services/receivers/providers launchable/bindable by other apps -> **authentication bypass**, unauthorized actions, intent injection. **Fix:** `exported="false"` for internal components; if exported, enforce a **signature-level permission** and re-check auth/session inside.
4. **Exported component with an `intent-filter`** - adding an intent-filter **makes a component exported by default** (pre-Android 12). **Fix:** explicitly set `android:exported="false"` for internal filters; Android 12+ forces an explicit `exported` declaration.
5. **Exported `ContentProvider`** - other apps can read/write the provider's data -> **data leakage, SQL injection, path traversal** (`content://` reaching internal files). **Fix:** `exported="false"`; enforce read/write permissions; `grantUriPermissions` narrowly; parameterize queries.
6. **`android:usesCleartextTraffic="true"`** (or missing network security config) - allows **plaintext HTTP** -> MITM. **Fix:** `usesCleartextTraffic="false"` + a **Network Security Config** enforcing HTTPS (and pinning where needed).
7. **Custom permissions with weak `protectionLevel`** (`normal` instead of `signature`) - a component "protected" by a permission any app can request is effectively unprotected -> **permission re-delegation / privilege escalation**. **Fix:** `protectionLevel="signature"`.
8. **`taskAffinity` / `launchMode` misconfig (StrandHogg)** - exported activities with custom `taskAffinity` or `singleTask`/`singleInstance` abused for **task hijacking / UI overlay**. **Fix:** `taskAffinity=""` on sensitive activities, avoid unnecessary `singleTask`, target a recent SDK.
9. **Over-privileged permissions (`uses-permission`)** - excessive permissions (SMS, location, contacts, `SYSTEM_ALERT_WINDOW`) expand attack surface and enable **tapjacking** or data harvesting. **Fix:** least privilege; remove unused; justify each.
10. **Auto-backup to cloud** - sensitive data auto-backed up to Google Drive, outside app control. **Fix:** exclude sensitive files via backup rules, or disable backup.
11. **Exported WebView-hosting activities** - load **attacker-controlled URLs** or expose JS bridges via deep-link params. **Fix:** `exported="false"`, validate incoming URIs, avoid `addJavascriptInterface` with untrusted content.
12. **`android:networkSecurityConfig` missing or misconfigured** - no pinning, user-added CAs trusted, cleartext permitted per-domain -> MITM. **Fix:** strict config: HTTPS-only, system CAs only, pin where appropriate.
13. **Exported `BroadcastReceiver` without permission** - any app can send a crafted broadcast -> trigger actions, inject data, DoS. **Fix:** `exported="false"` or require a signature permission; validate the broadcast's source and extras.
14. **`minSdkVersion` set too low** - supporting old Android inherits unpatched OS vulnerabilities and weaker defaults (cleartext allowed, user CA trust). **Fix:** raise `minSdkVersion` to a supported, hardened baseline.

**How I test these.** decompile with **apktool/JADX**, read `AndroidManifest.xml`, flag every `exported="true"`, `debuggable`, `allowBackup`, cleartext and weak-permission entry, then **confirm each dynamically** (`adb shell am start` for activities, `adb backup` for backup, `content query` for providers) before rating it. The headline: **the top manifest findings are `debuggable=true`, `allowBackup=true`, exported components without permissions, and cleartext traffic - all confirmed dynamically, not just flagged from the manifest.**

### All Android components with examples
**Activity** (UI screen - login screen), **Service** (background work - music playback/sync), **Broadcast Receiver** (system/app events - SMS received, boot completed), **Content Provider** (structured data sharing - Contacts provider). Security angle: any of these **exported** without proper permission = attack surface.

### Android permissions
Declared in the manifest; **protection levels**: **normal** (auto-granted), **dangerous** (runtime consent - location, contacts, camera), **signature** (granted only to apps **signed with the same key**), and **signatureOrSystem**. I check for **over-privileged** apps and **custom permissions with weak protection levels**.

### What is an Intent?
A **messaging object** for **IPC** between components. **Explicit** (names the target component - safe) vs **Implicit** (declares an action, system resolves it - can be **intercepted/hijacked** by a malicious app if not restricted). **Intent-based attacks:** intent redirection, hijacking, sniffing of implicit intents carrying sensitive data.

### Intent redirection & PendingIntent hijacking
**Intent redirection (forwarding).** the app takes an **attacker-supplied intent** (passed in as an extra) and calls `startActivity()`/`sendBroadcast()` on it, so the attacker reaches **internal, non-exported components** or leaks data through the trusted app's privileges - a classic high-impact bank-app finding.
**PendingIntent hijacking.** a **mutable** `PendingIntent` with an empty/implicit base intent lets a malicious app **fill it in** and act with the victim app's identity and permissions. **Fix:** `FLAG_IMMUTABLE` (default on API 31+), explicit base intents, and never forward an attacker-controlled intent.

### Using Drozer to detect authentication/IPC vulnerabilities
Drozer enumerates **attack surface** - `run app.package.attacksurface`, lists **exported activities/services/providers/receivers**. I then **invoke exported activities directly** (`app.activity.start`) to **bypass login screens**, **query content providers** (`app.provider.query`) for SQLi/path traversal, and **inject into exported receivers/services**. It's my go-to for proving **broken IPC access control**.

### Content provider attacks (SQLi & path traversal)
Exported `ContentProvider`s (or `grantUriPermissions` misuse) let other apps read/write data (`content://com.bank.provider/users`). Two injection classes:
- **SQL injection** - the provider builds a query from the caller's `selection`/`projection`/`sortOrder` without binding, so a crafted selection `1=1) UNION SELECT password FROM accounts--` dumps other tables. Drozer: `run app.provider.query content://...`, `run scanner.provider.injection -a <pkg>`.
- **Path traversal** - a file-backed provider's `openFile` serving `content://.../files/x` with `../../databases/app.db` reads arbitrary private files. Drozer: `run scanner.provider.traversal -a <pkg>`.
Enumerate first with `run app.provider.info -a <pkg>`. **Fix:** `exported=false` unless sharing is intended; permission-protect (signature level); **parameterised queries (bind `selectionArgs`)**; restrict `projection` to an allowlist; canonicalise `openFile` paths; scope `grantUriPermissions` tightly.

### React Native app testing
A React Native app ships its JavaScript as a bundle at **`assets/index.android.bundle`** (often **unminified**). Extract and read it for **business logic, hardcoded API keys, endpoints and secrets**; patch the bundle to disable pinning, or hook it at runtime. Traffic usually honours the system proxy (easier to intercept than Flutter, whose logic is compiled into `libflutter.so`). Always grep the bundle for secrets.

### Janus vulnerability
**CVE-2017-13156** - an APK signed with the **v1 (JAR) signature scheme** can have **arbitrary DEX bytes prepended** without breaking the signature, because v1 **doesn't cover the whole file**. The runtime executes the injected DEX while the OS still sees a "valid" signature -> **malware injection into a signed app**. Fixed by **v2+ signature schemes** (which hash the full APK) and affects **Android 5.0-8.0**.

### V1 APK signature / insecure signature schemes
**v1 = JAR signing** - signs **individual files, not the whole archive**, so it's vulnerable to **Janus** and ZIP-level tampering. **v2 (Android 7+)** = signs the **entire APK** (APK Signing Block). **v3 (Android 9+)** adds **key rotation**. **v4 (Android 11+)** = incremental/streaming. **Insecure = shipping with only v1**; I flag apps that don't use **v2+**.

### Flutter SSL pinning bypass + difficulties faced
Flutter **doesn't use the system proxy or the Android TrustManager** - it has its **own networking stack (Dart `dart:io`) statically linked in `libflutter.so`** using **BoringSSL**. So **standard Frida Java hooks and Burp proxy settings don't work**. The approach: **force traffic through the proxy** (e.g. set a proxy via `ProxyDroid`/iptables) and **hook BoringSSL's `ssl_verify_peer_cert` in `libflutter.so`** by **pattern-matching the function offset** (tools like **reFlutter** patch the Flutter engine, or Frida scripts that scan `libflutter.so`). **Difficulty:** the offset **changes per Flutter version/architecture**, so I often **rebuild the pattern or use reFlutter** to repackage the APK with pinning disabled and the proxy baked in.

### Frida: commands / detection / bypass Frida detection
Common: `frida-ps -Ua` (list apps), `frida -U -f <pkg> -l script.js`, `objection -g <pkg> explore`. **Frida detection** looks for: the **frida-server process/port (27042)**, **`frida` strings in memory/maps**, **`/data/local/tmp/frida`**, and **named pipes**. **Bypass detection:** **rename frida-server and run on a non-default port**, use **`frida-gadget` embedded** instead of server, **magisk + hiding modules**, **Frida scripts that hook the detection functions themselves**, or **`frida --no-pause` with stealth/early instrumentation**.

### If data is stored in SharedPreferences - is it a vulnerability? What if it's EncryptedSharedPreferences?
**Plain SharedPreferences = yes, a finding** if it holds **sensitive data** - it's **cleartext XML in `/data/data/<pkg>/shared_prefs/`**, readable on a **rooted device or via `allowBackup`**. **EncryptedSharedPreferences (Jetpack Security)** is **much better** - data is **AES-encrypted with keys in the Android Keystore**. But I still check: is the **Keystore key hardware-backed**? Is **`setUserAuthenticationRequired`** set? On a rooted device with the app unlocked, **Frida can still pull decrypted values at runtime**, so "encrypted at rest" != "safe against instrumentation."

### Exact Android path where hardcoded/stored credentials live
App-private data: **`/data/data/<package_name>/`** - specifically **`/shared_prefs/*.xml`** (SharedPreferences), **`/databases/`** (SQLite), **`/files/`**, and the **`/cache/`** dir. Hardcoded-in-code secrets are in **`classes.dex` / `strings.xml` / `resources.arsc`** inside the APK, and sometimes **native `.so` libs**. External/world-readable: `/sdcard/`.

### Signature permission (Android)
A **custom permission with `protectionLevel="signature"`** is granted **only to apps signed with the same certificate**. It's used to **secure IPC between a vendor's own apps**. I check whether a component is "protected" by a signature permission that's **actually enforced** - and whether a lower `protectionLevel` was used by mistake, exposing the component to any app.

### RASP
**Runtime Application Self-Protection** - defenses **built into the app** that react at runtime: **root/jailbreak detection, tamper/integrity checks, debugger/Frida detection, emulator detection, repackaging detection**. It raises the bar for instrumentation. I test by **enumerating each RASP check and bypassing them one by one** (Frida hooks, Magisk hiding), and I note that **good RASP is layered with native checks + server-side attestation**.

### If Frida/Objection is restricted, how do you approach the developer to capture the request?
I explain it's a **testing-environment need, not an attack** - I request one of: a **debug/non-hardened build** with RASP/pinning disabled for the test window, a **test build with the Burp CA pinned** (or pinning off), or **source/staging access**. The point I make to the dev: **I'm validating the server-side controls; client hardening shouldn't hide server vulnerabilities**, so a **testable build lets us assess the actual backend risk**. For **RE**, same ask - a **debuggable build or symbols** so assessment isn't blocked purely by client obfuscation. I document any control we disabled so it's clear it's **still present in production**.

### Which tools for which purpose in Android testing (quick map)
**jadx** -> decompile to Java; **apktool** -> decode/rebuild resources + manifest + smali; **MobSF** -> automated static+dynamic; **Frida/Objection** -> runtime hooking (pinning/root/biometric bypass, memory dump); **Drozer** -> IPC/exported-component attacks; **Burp** -> traffic interception; **Ghidra/IDA** -> native `.so` analysis; **adb** -> device interaction; **Magisk** -> root + hiding; **nuclei** -> scanning discovered endpoints.

---

## 5. Android vs iOS - key differences for a tester
iOS apps are sandboxed more tightly and distributed only via the App Store (signed, encrypted binaries), so you usually need a jailbreak and to decrypt the IPA before static analysis. Android is more open (sideloading, rooting, readable DEX), and exported IPC components are a bigger attack surface. Storage targets differ: Keychain/plist/Core Data on iOS vs SharedPreferences/SQLite on Android. Full iOS detail is in [ios-security.md](ios-security.md).
