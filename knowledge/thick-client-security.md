# Thick-Client Application Security - Reference & Interview Prep

Thick-client (fat-client / desktop) applications run significant logic on the user's own machine - Windows `.exe`/.NET, Java, C/C++ - while talking to a backend database or services. Testing them mixes **web-style bugs on the backend calls** with **binary/OS bugs in the client itself**, so you work across a proxy, a disassembler/decompiler and the local filesystem/registry at the same time. Vulnerabilities follow the same **What -> Why -> How -> Impact -> Mitigations** shape used across these notes.

Networking, TLS and crypto basics are in [network-and-fundamentals.md](network-and-fundamentals.md); the web vulnerabilities that show up on the backend (SQLi, auth, access control) are in [web-security.md](web-security.md).

---

## 1. Architecture & methodology

### Two-tier vs three-tier
- **Two-tier** - the client talks **directly to the database**. The DB connection string (often with credentials) lives on the client, and every user effectively has network access to the database. Common in legacy enterprise apps and a high-severity finding by itself.
- **Three-tier** - client -> application server -> database. The client never holds DB credentials; the app server mediates, so most testing shifts to the server-side API.

### Proxy-aware vs non-proxy traffic
- **HTTP/S, proxy-aware** - point the app (or the OS/WinINET proxy) at Burp and test it like a web API.
- **HTTP/S that ignores proxy settings** - force traffic through Burp with its invisible proxy plus a `hosts` redirect, or with Proxifier.
- **Non-HTTP / raw TCP** - intercept with **Echo Mirage**, **Mallory**, or a TCP interceptor; analyse the protocol in **Wireshark**.

### Toolkit
- **PE / binary inspection** - CFF Explorer, PEiD, Detect It Easy (language, packer, imports).
- **Runtime behaviour** - Process Monitor (file/registry/process activity), Process Explorer, API Monitor, regshot (registry before/after diff).
- **Disassembly / debugging** - Ghidra, IDA, x64dbg/OllyDbg (native); **dnSpy**/ILSpy (.NET decompile and edit); JD-GUI/Procyon (Java).
- **Runtime instrumentation** - Frida (hook functions, change return values), Objection.
- **Secrets / strings** - `strings`, BinText, and grep over config files.

### Methodology
1. **Information gathering** - identify the language/framework, inspect the PE, map which files and registry keys the app touches (Process Monitor).
2. **Traffic analysis** - intercept and test every backend call (auth, access control, injection) as a web API.
3. **Static analysis** - decompile (.NET/Java are near-source), pull hardcoded secrets, connection strings, endpoints and crypto misuse.
4. **Dynamic analysis** - debug/hook the running process, inspect memory, bypass client-side checks.
5. **Local storage review** - config files, registry, logs, memory, temp files.
6. **Privilege & deployment** - DLL hijacking, service permissions, update integrity, code signing.

---

## 2. Common thick-client findings

### Hardcoded secrets & connection strings
**What it is.** Credentials, API keys, encryption keys or full DB connection strings embedded in the binary or shipped config.

**Why it happens.** Developers assume the compiled client is opaque; .NET and Java decompile back to near-source, and native binaries still yield strings.

**How you test it.** Run `strings`/BinText over the binary and config files; decompile with dnSpy/JD-GUI; diff registry and files with Process Monitor to find where secrets are read. A two-tier app almost always hides a DB connection string here.

**Impact.** Direct database/service access, forged requests, and decryption of "protected" local data.

**Mitigations.** Keep secrets server-side; never ship DB credentials in a client; if a value must be local, store it in the OS secret store (DPAPI/Credential Manager/Keychain) and scope it tightly.

### Insecure local storage (files & registry)
**What it is.** Sensitive data - tokens, PII, licence/entitlement flags, passwords - stored in plaintext or weakly "encrypted" in config files, the registry, logs or temp files.

**How you test it.** Watch reads/writes with Process Monitor, inspect the files and `HKCU`/`HKLM` keys, and look for base64 or trivially reversible "encryption".

**Impact.** Disclosure of credentials/PII and tampering with client-side entitlement flags.

**Mitigations.** Encrypt at rest with a platform key store, store no more than necessary, and never trust a client-side flag for authorization.

### Two-tier direct database access
**What it is.** The client connects straight to the DB, so any user can reach it with the embedded credentials.

**How you test it.** Recover the connection string, connect with a DB client, and enumerate privileges - frequently the app account is over-privileged (DBA, or write everywhere).

**Impact.** Full data read/modify, and privilege-escalation to the DB host.

**Mitigations.** Move to a three-tier design with a mediating service; failing that, least-privilege DB accounts and network restrictions.

### DLL hijacking / DLL preloading
**What it is.** The app loads a DLL by name without a full trusted path, so a malicious DLL placed earlier in the search order is loaded and run in the app's process (and privilege).

**Why it happens.** `LoadLibrary`/implicit imports resolve against the current/working directory or a writable application directory on the DLL search path.

**How you test it.** Use Process Monitor to spot `NAME NOT FOUND` on DLLs the app probes in writable locations, then drop a proof DLL of that name and confirm it loads.

**Impact.** Code execution, and local privilege escalation when the app runs elevated.

**Mitigations.** Load DLLs by absolute path from a protected directory, call `SetDefaultDllDirectories`/use safe search mode, sign DLLs and verify them, and remove write permissions on application directories.

### Insecure IPC
**What it is.** Named pipes, local sockets, shared memory, COM or custom local channels that accept commands without authenticating the caller or validating input.

**How you test it.** Enumerate the app's IPC endpoints (Process Explorer handles, pipe listings), then send crafted messages and observe privileged actions or injection.

**Impact.** Privilege escalation and command/data injection from a low-privileged local process.

**Mitigations.** Authenticate and authorise the caller, set restrictive ACLs on the IPC object, and validate every message.

### Weak or absent binary protections & no code signing
**What it is.** Release builds with no obfuscation, debugging enabled, missing compiler mitigations, or an unsigned binary/updater.

**How you test it.** Inspect the PE for ASLR/DEP/control-flow-guard flags (CFF Explorer, BinSkim), check for a valid Authenticode/code signature, and see whether the app is debuggable/patchable.

**Impact.** Easier reverse engineering and tampering, and acceptance of a patched or malicious binary/update.

**Mitigations.** Enable ASLR, DEP/NX, CFG and stack protections; obfuscate release builds; and sign binaries and updates, verifying signatures before execution.

### Secrets in memory
**What it is.** Credentials, keys or decrypted data left in process memory longer than needed, readable with a debugger or memory dump.

**How you test it.** Attach a debugger or dump the process and search memory for known markers.

**Impact.** Disclosure of plaintext secrets even when at-rest storage is sound.

**Mitigations.** Zero sensitive buffers promptly, use protected-memory APIs where available, and minimise how long secrets are held.

### Client-side trust & improper access control
**What it is.** The client enforces authorization, feature gating or validation that the server then trusts - so patching the client, hooking a function (Frida), or editing a response unlocks it.

**How you test it.** Hook or patch the check (e.g. make `isLicensed()`/`isAdmin()` return true in dnSpy or Frida) and see whether the backend still honours the action.

**Impact.** Authorization and licensing bypass, and logic abuse.

**Mitigations.** Enforce every security decision server-side; treat the client as untrusted.

### Injection to the backend
**What it is.** The client's inputs flow into backend SQL, OS commands or queries - the web injection classes reached through a desktop front-end.

**How you test it.** Intercept the backend calls and test them exactly as in [web-security.md](web-security.md) (SQLi, command injection, auth/access control).

**Mitigations.** Parameterise queries and validate server-side, as for any web backend.

### Insecure update mechanism
**What it is.** An auto-updater that fetches over cleartext or without verifying a signature, letting a MITM deliver a malicious update.

**Mitigations.** Update over TLS, verify a signature on the downloaded package before applying, and pin the update host/certificate.

---

## 3. Memory-corruption in native clients

These apply to native C/C++ clients, and equally to **native libraries invoked from managed apps** - including **Android NDK `.so` libraries** (so they also belong to a mobile assessment, see [android-security.md](android-security.md)).

### Buffer Overflow
**What it is.** Writing more data into a fixed-size buffer than it can hold, overwriting adjacent memory on the stack or heap. On the stack, overwriting the saved return address redirects execution to attacker-chosen code.

**Why it happens.** Unsafe C/C++ functions (`strcpy`, `gets`, `sprintf`, `memcpy`) copy attacker-controlled data with no bounds check on its length.

**How you test and exploit it.** Supply over-long input to a vulnerable field, file or network message and look for a crash; find the offset that overwrites the instruction pointer (a cyclic pattern), gain control of EIP/RIP, identify bad characters, then - working around ASLR, DEP/NX and stack canaries - redirect to shellcode or a ROP chain. The classic workflow is *fuzz -> crash -> find offset -> control EIP -> avoid bad chars -> `JMP ESP` -> shellcode*.

**Impact.** Crash/denial of service and arbitrary code execution.

**Mitigations.** Use memory-safe functions and, where possible, memory-safe languages; enable compiler defences (stack canaries/`/GS`, DEP/NX, ASLR, CFG, `FORTIFY_SOURCE`); bounds-check all input; and fuzz native parsers.

### Format String Attack
**What it is.** Passing attacker-controlled input as the *format string* of a `printf`-family function - `printf(user)` instead of `printf("%s", user)` - so format specifiers inside the input are interpreted.

**Why it happens.** The function acts on the specifiers it finds: `%x`/`%p` read and leak stack memory, `%s` dereferences a pointer, and `%n` writes the number of bytes printed so far to an address - giving both a read and a write primitive.

**How you test and exploit it.** Inject `%x %x %x...` to dump the stack and leak memory (useful to defeat ASLR), then use `%n` to write to a chosen address - overwriting a saved return address or a GOT entry - to redirect execution.

**Impact.** Information disclosure and an arbitrary read/write that escalates to code execution.

**Mitigations.** Never pass user input as the format string - always use a fixed format (`printf("%s", user)`); and enable `-Wformat -Wformat-security` so the compiler flags it.

---

## 4. Interview-style answers
- **"Why do thick clients need a different approach from web apps?"** The attacker
  controls the whole runtime - binary, memory, filesystem, and network path - so
  any auth/license/`isAdmin` check enforced on the client can be patched out.
  Secrets live locally, traffic is often non-HTTP, and native code can have
  memory-corruption bugs. Nothing enforced only on the client is a real control.
- **"Two-tier vs three-tier - why does it matter?"** Two-tier connects the client
  straight to the database, so the connection string (often with DB creds) ships
  in the client and the client builds SQL itself (hardcoded creds + direct SQLi).
  Three-tier puts an app/API server in between, so it tests more like a web app.
  Identifying the tier tells you where the bugs and the interception strategy are.
- **"How do you intercept non-HTTP thick-client traffic?"** Escalate: system/app
  proxy to Burp for proxy-aware HTTP; Proxifier/hosts-redirect/invisible-proxy for
  non-proxy-aware; for raw TCP/custom binary use Wireshark to observe and Frida to
  hook `send`/`recv` and read plaintext before encryption; for 2-tier, sniff the
  DB wire protocol and extract the connection string from memory.
- **"What is DLL hijacking / side-loading?"** An app loads a DLL by name from a
  writable or earlier-search-path location; dropping a malicious DLL there runs
  code with the app's privileges (map missing DLLs with Procmon "NAME NOT FOUND").
  A common thick-client privilege-escalation and persistence vector.

## 5. Quick checklist
- Identify tier (does the client hold DB credentials?) and whether traffic is proxy-aware.
- Decompile (.NET/Java) and string-scan (native) for secrets, connection strings, endpoints, keys.
- Intercept and test every backend call as a web API (auth, access control, injection).
- Review local storage: config files, registry, logs, temp, memory.
- Check DLL search-order hijacking, IPC endpoints, and service/file ACLs.
- Verify binary mitigations (ASLR/DEP/CFG), code signing, and update integrity.
- For native code, fuzz parsers for buffer-overflow/format-string bugs.
- Confirm no security decision is enforced client-side only.
