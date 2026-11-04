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
