# iOS Application Security - Interview Q&A

iOS app pentesting. Same OWASP Mobile Top 10 (2024) and MASVS / MASTG as Android - the summary table and MASVS groups are in [android-security.md](android-security.md#1-owasp-mobile-top-10-2024). As with Android, most "mobile" findings are really API findings surfaced through the app, so test the backend with equal rigour (see [api-security.md](api-security.md)).

*(Be honest in an interview if your hands-on work is Android: "My hands-on mobile work is Android; I know the iOS approach and can pick it up quickly." Then show you know the material below.)*

---

## 1. iOS methodology

### Walk me through an iOS pentest.
1. **Setup** - jailbroken device (checkra1n/palera1n) with Frida, Objection and SSH; a Mac with Xcode tooling helps.
2. **Acquire & decrypt** - App Store binaries are encrypted (FairPlay); dump a decrypted IPA from a jailbroken device with **frida-ios-dump** before static analysis.
3. **Static** - read `Info.plist` (ATS settings, URL schemes, `UIFileSharingEnabled`), `class-dump`/Hopper/Ghidra for the Objective-C/Swift interface, and search for hardcoded secrets.
4. **Dynamic** - intercept traffic through Burp, bypass SSL pinning and jailbreak detection with Frida/Objection, and test the backend APIs like any web API.
5. **Storage** - inspect Keychain, `NSUserDefaults`, plist files, SQLite and Core Data under the app's sandbox.
6. **Map to MASVS/MASTG**, then report.

### IPA structure?
An IPA is a ZIP containing `Payload/<App>.app/` with the Mach-O executable, `Info.plist`, resources, embedded provisioning profile and `_CodeSignature`. On an App Store build the Mach-O is encrypted until dumped from memory on a jailbroken device.

### How do you test without a jailbreak?
Many shops forbid jailbreaking the test device, or no jailbreak exists for the OS version. The standard approach is to **re-sign the app with a Frida gadget**: unzip the IPA, inject the `FridaGadget.dylib` into the Mach-O (patch its load commands with `optool`/`insert_dylib`), re-sign with your own provisioning profile (`codesign` / tools like **objection patchapk** or `ios-deploy`), and reinstall. The embedded gadget gives you Frida instrumentation (hook functions, bypass pinning/jailbreak checks, dump crypto) on a stock device - at the cost of not being able to run the jailbreak-only dumping tools (Clutch, keychaindumper). You still proxy traffic and test the backend API normally.

### What is FairPlay, and why decrypt?
App Store binaries are DRM-encrypted with Apple's FairPlay; `strings`/class-dump on the on-disk binary returns garbage. The binary is decrypted in memory at launch, so tools like **frida-ios-dump**/bagbak dump the decrypted image from a running process (jailbroken) before static analysis.

### How do you proxy iOS traffic?
Set Burp as the device's HTTP proxy and install Burp's CA profile, then **trust it fully** under Settings -> General -> About -> Certificate Trust Settings (installing the profile is not enough on iOS). For apps that ignore the system proxy or pin, use Frida/Objection to disable pinning first.

---

## 2. iOS - common findings

### How do you bypass SSL pinning?
Objection (`ios sslpinning disable`), Frida scripts hooking `SecTrustEvaluate`/`NSURLSession`/AFNetworking/TrustKit, or SSL Kill Switch on a jailbroken device. **Developer fix:** pin to a backup key, combine with jailbreak/tamper detection, and don't rely on pinning alone.

### How do you bypass jailbreak detection?
Objection `ios jailbreak disable`, Frida hooks on the checks (file-existence of `/Applications/Cydia.app` or `/bin/bash`, `fork()`/`canOpenURL:` probes, sandbox-write tests), or Liberty/Shadow tweaks. **Developer fix:** layer multiple independent checks, obfuscate them, and back them with a server-side signal (DeviceCheck/App Attest) rather than client-only detection.

### Insecure data storage examples?
Tokens/PII in `NSUserDefaults` (plaintext plist), unprotected Keychain items (wrong accessibility class, e.g. `kSecAttrAccessibleAlways`), plaintext SQLite/Core Data, secrets in cached files or in the app sandbox on an unencrypted backup. **Fix:** store secrets in the Keychain with `WhenUnlockedThisDeviceOnly`, use Data Protection file classes, and keep nothing sensitive in `NSUserDefaults`.

### Insecure local data / ATS?
App Transport Security (ATS) should force TLS; check `Info.plist` for `NSAllowsArbitraryLoads`/per-domain exceptions that permit cleartext or weak TLS. **Fix:** remove ATS exceptions, require TLS 1.2+.

### URL scheme & Universal Link issues?
Custom URL schemes (`myapp://`) can be registered by other apps, so a scheme that performs actions or passes secrets is hijackable; Universal Links are safer but must validate the inbound URL/caller. **Fix:** prefer Universal Links with server-verified `apple-app-site-association`, validate every inbound parameter, and never trust a scheme for auth.

### Inter-app / IPC issues?
Insecure handling of data received via URL schemes, `UIActivity`/share extensions, app groups and pasteboard. The **pasteboard** (especially the general pasteboard) can leak sensitive copied data to other apps. **Fix:** validate all inbound data, scope app-group storage, and avoid putting secrets on the general pasteboard.

### Screenshot / backgrounding leakage?
iOS snapshots the current screen when an app is backgrounded (for the app switcher); a sensitive screen is cached to disk in the snapshot. **Fix:** blank or obscure sensitive views in `applicationDidEnterBackground` (overlay/`isHidden`).

### Binary protections?
Missing PIE/ASLR, stack canaries, or anti-debugging (`ptrace(PT_DENY_ATTACH)`), and no obfuscation make reversing and runtime tampering easy. **Fix:** enable compiler mitigations, add anti-debugging and jailbreak/tamper detection, and obfuscate sensitive logic - as defence-in-depth, not a sole control.

### Keychain & biometric auth bypass?
Keychain items guarded by Face ID/Touch ID can sometimes be reached if the access-control flags are weak, or the biometric gate is enforced only in the UI. **Fix:** protect items with `SecAccessControl` (`.biometryCurrentSet`/`.userPresence`) so the key material itself is gated, not just a UI check.

---

## 3. Android vs iOS - key differences for a tester
iOS apps are sandboxed more tightly and distributed only via the App Store (signed, encrypted binaries), so you usually need a jailbreak and to decrypt the IPA before static analysis. Android is more open (sideloading, rooting, readable DEX), and exported IPC components are a bigger attack surface. Storage targets differ: Keychain/plist/Core Data on iOS vs SharedPreferences/SQLite on Android. Android detail is in [android-security.md](android-security.md).

---

## 4. iOS fundamentals & security model

**Architecture / security model**
- **Closed ecosystem**: apps come only from the App Store, each reviewed and **code-signed** by Apple. No sideloading without a dev cert. (Android allows APK sideloading; iOS doesn't.)
- **App sandbox**: every app runs in its own container, isolated from others and the OS. Each app has its own directory tree.
- **Code signing & mandatory signature verification**: iOS only runs signed code. This is why you need a **jailbreak** to run your own tools (Frida, SSH) on the device.
- **Secure Boot chain**: Boot ROM -> iBoot -> kernel, each stage verifies the next. This is what jailbreaks attack.
- **Data Protection / encryption**: files are encrypted with keys tied to the device passcode and hardware (the **Secure Enclave**). Files have protection classes (e.g. "complete", "until first unlock").
- **Keychain**: the secure storage for secrets (tokens, passwords, keys), hardware-backed. This is the iOS equivalent of Android's **Keystore + EncryptedSharedPreferences**.

**App format**
- iOS apps are **IPA** files (vs Android **APK**). An IPA is a zip containing the **.app** bundle.
- Inside: the **Mach-O binary** (the compiled executable, vs Android's `classes.dex`), **Info.plist** (app config, vs AndroidManifest.xml), resources, and frameworks.
- Written in **Objective-C** or **Swift** (vs Java/Kotlin).
- App Store binaries are **encrypted (FairPlay DRM)** - you must **decrypt** them before static analysis (a big difference from Android, where you just unzip and decompile).

**App data locations on the device**
- **Bundle** (the app itself, read-only): `/var/containers/Bundle/Application/<UUID>/`
- **Data container** (where app data lives): `/var/mobile/Containers/Data/Application/<UUID>/` - contains `Documents/`, `Library/` (incl. `Preferences/` for plists, `Caches/`), `tmp/`. This is the iOS equivalent of Android's `/data/data/<package>/`.

**Info.plist / NSUserDefaults / plist**
- **Info.plist** - the app's config manifest. Security-relevant keys: `NSAppTransportSecurity` (ATS settings - can disable TLS enforcement per-domain, a common finding when `NSAllowsArbitraryLoads` is true), `NSFaceIDUsageDescription`/other usage strings, custom URL scheme declarations (`CFBundleURLTypes`) which can be hijacked if not validated, and exported capabilities.
- **NSUserDefaults** - iOS's simple key-value local storage (like Android's SharedPreferences). It's **plaintext on disk**, unencrypted, backed up to iCloud/iTunes by default unless excluded. Common finding: apps storing tokens, PII, or flags (`isPremiumUser`, auth tokens) here instead of Keychain. Check `Library/Preferences/<bundle_id>.plist` on a jailbroken device.
- **plist** (Property List) - the general serialization format (XML or binary) iOS uses for config and data storage - Info.plist, NSUserDefaults, and app-specific data files are all plists. On a jailbroken/decrypted app you inspect these directly (`plutil -convert xml1` to read binary plists).

**Local data storage (beyond NSUserDefaults/Keychain basics)**
- **Keychain** - the secure storage API (unlike NSUserDefaults). Encrypted at rest, but check `kSecAttrAccessible` settings - `WhenUnlockedThisDeviceOnly` is strong, `Always` or `AfterFirstUnlock` (without `ThisDeviceOnly`) means it's included in backups and accessible even device-locked in some cases.
- **Core Data / SQLite databases** - app's local DB, usually unencrypted unless the app adds SQLCipher. Check for cached PII, tokens, or chat/message content.
- **Realm databases** - another common local DB; same deal, check encryption.
- **Caches directory / tmp directory** - often holds cached API responses, images, sometimes sensitive JSON - not encrypted, not backed up but still readable on a jailbroken device.
- **Keyboard cache / UIPasteboard** - autocorrect learning and the system clipboard can leak sensitive typed data; check if the app disables them for password/PII fields.
- **Snapshot/screenshot caching** - iOS auto-screenshots the app on backgrounding (app switcher). Sensitive screens (balances, PII) should blur/hide before backgrounding - missing this is a classic finding.

**Inter-app / IPC**
- **URL schemes (custom, e.g. `myapp://`)** - like Android intents; test for parameter injection, unauthenticated deep-link actions (password reset via deep link, auth bypass).
- **Universal Links** - HTTPS-based deep links verified via `apple-app-site-association` file on the domain - more secure than custom schemes if implemented right, check if that association file is properly restrictive.
- **App Extensions** (share extension, keyboard extension, widget) - separate sandboxed processes; check data sharing via App Groups for leakage.
- **App Groups / shared container** - multiple apps/extensions from the same developer sharing a sandboxed folder - check permissions and what's stored there.

**Binary / app protections**
- **Swift vs Objective-C runtime** - Obj-C's dynamic messaging makes Frida/method-swizzling hooking easy; Swift (especially with whole-module optimization) is harder to hook dynamically, often needs symbol/offset-based Frida hooking instead of class-dump style.

**Build/signing**
- **Entitlements** - declared capabilities (Keychain access groups, associated domains, push, etc.) in the provisioning profile - review for over-permissioning.
- **Code signing** - every binary must be signed; jailbreaks bypass this (fake-signing/`ldid`) to run patched/injected binaries.

---

## 5. Setting up for iOS testing

**Jailbreak** (needed for root access, Frida, SSH - like rooting Android):
- **checkra1n / palera1n** - based on the **checkm8** bootrom exploit, hardware-level, unpatchable, works on A5-A11 devices. Most reliable for a stable test device.
- **unc0ver, Taurine, Dopamine** - kernel-exploit based, for newer devices/iOS versions.

**Rootful vs rootless jailbreak.** A **rootful** jailbreak gives full write access to `/` (the root filesystem) - the traditional model (checkra1n, unc0ver). A **rootless** jailbreak does **not** modify the root filesystem (forced by iOS 15+ / arm64e constraints); it installs to **`/var/jb`** and is more limited but works on newer devices (**Dopamine**, palera1n rootless). It affects where tools and files land, so know which one your device uses.

**Minimum iOS version you can test on** depends on **jailbreak availability** for that device/version: practically, test on a **jailbreakable device** - checkm8/checkra1n for A-series up to A11, or palera1n/Dopamine (rootless) for newer. If the app sets a **minimum deployment target**, test on that version or above.

**Tools (the iOS toolkit).**
- **Frida / Objection** - dynamic instrumentation, SSL pinning and jailbreak-detection bypass (same as Android).
- **Burp Suite** - intercept traffic (install the Burp CA profile on the device).
- **class-dump** - extract Objective-C class/method headers from the binary (helps you find methods to hook).
- **Hopper / Ghidra / IDA** - disassemble the Mach-O binary.
- **frida-ios-dump** - decrypt and pull the app binary off the device (defeats FairPlay encryption).
- **Cycript** - older runtime manipulation tool.
- **Keychain-Dumper** - dump Keychain contents on a jailbroken device.
- **SSH / Filza** - browse the filesystem.
- **otool / nm** - inspect the binary (check encryption, protections).
- **plutil** - read/convert plist files.
- **bagbak / flexdecrypt** - alternative FairPlay decryptors; **Grapefruit** - web UI for runtime inspection of files, Keychain, classes and modules.

---

## 6. iOS reverse engineering tooling

### FairPlay (deep dive)
**FairPlay** is Apple's DRM (Digital Rights Management) system used to encrypt App Store binaries so they can only run on devices that purchased/downloaded them through Apple's infrastructure.

**How it works.**
- When you download an app from the App Store, Apple encrypts the Mach-O binary's executable segment using a key tied to your Apple ID / device.
- The decryption key isn't stored in the IPA or on disk in usable form - it's provisioned by Apple's servers at install time and held by the OS, not directly exposed to the app or user.
- On disk, the binary looks like a normal Mach-O but has an `LC_ENCRYPTION_INFO` (or `LC_ENCRYPTION_INFO_64`) load command marking a region as FairPlay-encrypted. That region is gibberish until decrypted.

**How testers "bypass" it** - this isn't cracking the crypto, it's a well-known architectural property: the OS must decrypt the binary into memory to execute it. So the plaintext exists in RAM the moment the app runs. Tools don't break FairPlay's encryption - they dump the already-decrypted memory image and reconstruct a valid IPA from it.
- **frida-ios-dump / bagbak / flexdecrypt** work on a **jailbroken device**. They launch the target app (the OS decrypts it as part of normal launch), attach via Frida, walk the process memory to find the decrypted `__TEXT` segment and copy it out, patch the `LC_ENCRYPTION_INFO` load command to mark the segment as not encrypted (`cryptid = 0`), and repackage a new `.ipa`.
- **No key is ever recovered or brute-forced.** The technique relies on a jailbreak giving memory-inspection/process-attach rights the sandbox normally denies, and on the OS decrypting the app for you as a side effect of running it legitimately. It only works on jailbroken devices - non-jailbroken iOS blocks the memory introspection (`task_for_pid`, ptrace, code injection) these tools need.

### Hopper Disassembler
A static analysis/disassembler tool (like IDA/Ghidra) for Mach-O binaries, popular for iOS because it's Mac-native and lighter-weight.
1. **Decrypt the binary first** (via frida-ios-dump/bagbak) - Hopper can't make sense of the FairPlay-encrypted segment.
2. **Load the decrypted Mach-O** into Hopper. It disassembles ARM64 instructions and builds a pseudo-code view.
3. **Navigate via symbols/strings** - the Strings window finds hardcoded URLs, API keys, error messages, or endpoint paths; the Labels/Procedures list browses Objective-C methods and C functions.
4. **Cross-reference (XRefs)** - right-click any string or symbol -> "References to" to trace from a hardcoded string back to the function logic (e.g. find where a "jailbreak detected" string is referenced to locate the detection function).
5. **Patch binaries** - modify instructions (NOP out a jailbreak-check branch, flip a conditional jump) and re-export a patched Mach-O; needs re-signing (`ldid`) to run on a jailbroken device.
6. **Pseudo-code view** - for Objective-C methods, Hopper reconstructs a rough `objc_msgSend`-based call structure, readable enough to follow logic flow.

Limitation: Objective-C's dynamic dispatch (`objc_msgSend`) means Hopper shows you *that* a method was called, not always a clean typed signature - that's where class-dump comes in.

### class-dump
A command-line tool that extracts the **Objective-C class/method/property interface** from a compiled binary's runtime metadata (Objective-C binaries embed this metadata because the runtime needs it for dynamic dispatch - a goldmine that doesn't exist in pure Swift or C++).
1. Run `class-dump <decrypted_binary>` (or `class-dump-dyld` for binaries using the shared cache).
2. Output: header-file-like `.h` declarations for every class - class names and inheritance, all method signatures (`-(void)loginWithUsername:(NSString*)user password:(NSString*)pass;`), and property declarations (including non-obvious ones like `isJailbroken`, `isPremiumUnlocked`, `authToken`).
3. **Why it matters for testing:** it instantly reveals the app's internal API surface - method names hint at functionality (`- (BOOL)validateReceiptWithServer;`). You feed the class/method into **Frida** to hook that exact `ClassName.methodName` and override its return value (e.g. force `isJailbroken` to return `NO`); combine with Hopper (which shows *how* methods are implemented).

**Typical combined flow.** frida-ios-dump (decrypt) -> class-dump (get method map) -> Hopper (study/patch implementation) -> Frida (runtime hook) -> objection (automate common bypasses). Note: Swift classes without `@objc` exposure won't show up well in class-dump - for pure Swift apps you rely more on Hopper/IDA symbol tables and demangled Swift symbol names.

---

## 7. Android -> iOS cheat sheet

| Concept | Android | iOS |
|---|---|---|
| App package | APK | IPA |
| Compiled code | DEX (smali/Java) | Mach-O (Obj-C/Swift) |
| Manifest | AndroidManifest.xml | Info.plist |
| Secure storage | Keystore / EncryptedSharedPreferences | **Keychain** |
| Insecure storage | SharedPreferences | **NSUserDefaults / plist** |
| App data dir | `/data/data/<pkg>/` | `/var/mobile/Containers/Data/Application/<UUID>/` |
| Root access | Root (Magisk) | **Jailbreak** (checkra1n) |
| Decompile | JADX / apktool | class-dump / Hopper (after **decryption**) |
| Deep links | Intents / deep links | **URL schemes / Universal Links** |
| Decompile is easy? | Yes, just unzip | **No - binary is FairPlay-encrypted**, must decrypt first |
| Cleartext config | `usesCleartextTraffic` | **ATS (`NSAllowsArbitraryLoads`)** |
| Root/JB bypass | Objection `android root disable` | Objection `ios jailbreak disable` |
| Pinning bypass | `android sslpinning disable` | `ios sslpinning disable` |

---

## 8. More iOS interview Q&A

### Where does an iOS app store data, and what do you check?
In the **Data container** (`/var/mobile/Containers/Data/Application/<UUID>/`): `Documents/`, `Library/Preferences/` (plists/NSUserDefaults), Caches, SQLite/Core Data. I check for **sensitive data in plaintext** in NSUserDefaults/plists, and whether secrets are correctly in the **Keychain** with a strong accessibility class.

### What is the Keychain?
iOS's **hardware-backed secure storage** for secrets (tokens, keys, passwords), equivalent to Android's Keystore. I check **what's stored** and its **accessibility attribute** (e.g. `kSecAttrAccessibleAlways` / `...AfterFirstUnlock` are weaker than `WhenUnlockedThisDeviceOnly`). On a jailbroken device I dump it with **Keychain-Dumper**.

### How do you test biometric (Touch ID / Face ID)?
Check if it's a **simple success callback** - `LAContext.evaluatePolicy(...)` whose completion handler just returns a boolean, bypassable by hooking that callback with Frida/Objection to force success - or **cryptographically bound** via the **Secure Enclave / Keychain** (secure - the key only releases on real biometric, so hooking the callback doesn't help). The secure pattern ties `SecAccessControl` (`.biometryCurrentSet`) to a Keychain item rather than trusting the `evaluatePolicy` boolean.

### UIWebView vs WKWebView?
`UIWebView` is **deprecated and insecure** (whole-process, weaker isolation); `WKWebView` runs out-of-process and is safer. I check for untrusted content loading and **JS-to-native bridges** that expose sensitive functions.

### What is the Secure Enclave?
A separate **hardware security coprocessor** that handles keys, biometrics, and crypto operations in isolation from the main processor. Keys generated there never leave it, which is what makes Keychain + biometric binding strong.

### What's in Info.plist that interests you?
**ATS settings** (`NSAllowsArbitraryLoads`), **URL schemes** (`CFBundleURLTypes`), **permissions/usage strings**, **background modes**, and any **hardcoded secrets or URLs**.
