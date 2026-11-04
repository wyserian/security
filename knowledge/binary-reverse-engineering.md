# Binary Analysis & Reverse Engineering - Reference & Interview Prep

Binary work is understanding and attacking compiled programs with no source:
reversing a binary to recover its logic, and exploiting memory-corruption bugs
to control execution. It underpins malware analysis, thick-client and IoT
testing, CTF pwn, and exploit development. The two halves are **static/dynamic
RE** (what does it do, where is the bug) and **exploitation** (turn the bug into
control). Memory-corruption findings follow the usual
**What -> Why -> How -> Impact -> Mitigations** shape.

Native client context is in [thick-client-security.md](thick-client-security.md);
buffer-overflow/format-string basics also appear there.

---

## 1. Foundations

### Executable formats & memory
- **PE** (Windows `.exe`/`.dll`), **ELF** (Linux), **Mach-O** (macOS). Sections:
  `.text` (code), `.data`/`.bss` (globals), `.rodata` (constants),
  import/export tables.
- Process memory: stack (local vars, return addresses, grows down), heap
  (dynamic allocation), with code and data segments mapped in.
- Calling conventions matter for exploitation: x86 args on stack; x86-64
  System V uses `rdi, rsi, rdx, rcx, r8, r9`; return address saved on the stack.

### Static vs dynamic analysis
- **Static** - read without running: disassembly/decompilation, strings,
  imports, control flow. Safe, complete-ish, slower to understand.
- **Dynamic** - run and observe: debugger, breakpoints, memory/registers,
  tracing syscalls/API calls. Shows real behaviour, needs a safe sandbox
  (especially for malware).

## 2. Memory-corruption classes
### Stack buffer overflow
**What.** Writing past a stack buffer overwrites the saved return address.
**Why.** Unbounded copies (`strcpy`, `gets`, `sprintf`) with no length check.
**How.** Send input longer than the buffer; find the offset to the return
address (cyclic pattern), redirect to shellcode or a ROP chain.
**Impact.** Arbitrary code execution / control of the program.
**Mitigations.** Stack canaries, bounds-checked APIs, non-exec stack (NX/DEP),
ASLR, compiler hardening (`-fstack-protector`, FORTIFY).

### Heap overflow / use-after-free
**What.** Corrupt heap metadata or reuse freed memory still referenced.
**Why.** Missing bounds checks; dangling pointers after `free`.
**How.** Groom the heap, overflow into an adjacent chunk or reclaim a freed
object to control a function pointer/vtable.
**Impact.** Code execution or control-flow hijack.
**Mitigations.** Safe allocators, hardened `free`, AddressSanitizer in testing,
avoid raw pointers (smart pointers / RAII).

### Format string
**What.** User data used as a format string (`printf(user)`).
**Why.** Missing format specifier.
**How.** `%x`/`%p` leak stack, `%n` writes to memory (arbitrary write).
**Impact.** Info leak (defeat ASLR) or memory write -> code execution.
**Mitigations.** Always `printf("%s", user)`; compiler format warnings.

### Integer overflow
**What.** Arithmetic wraps and produces a too-small allocation or bad bound.
**Impact.** Downstream heap/stack overflow.
**Mitigations.** Checked arithmetic, validate sizes before allocation.

## 3. Modern mitigations (and why exploits chain)
- **ASLR** randomizes addresses -> need an info leak to find them.
- **NX/DEP** makes the stack non-executable -> use **ROP** (reuse existing code
  gadgets) instead of injected shellcode.
- **Stack canaries** detect overwrites before return -> leak or avoid the canary.
- **PIE / RELRO / CFG** harden further.
Real exploits usually chain a leak (beat ASLR) with a control primitive (ROP).

## 4. Interview-style answers
- **"Static vs dynamic RE?"** Static reads the binary without running it
  (disassembly, strings, imports); dynamic runs it under a debugger to watch
  real behaviour. You use both - static to locate, dynamic to confirm.
- **"How does NX change exploitation?"** You can no longer execute injected
  shellcode on the stack, so you reuse existing executable code via ROP/ret2libc.
- **"What is a canary and how do attackers beat it?"** A random value placed
  before the return address and checked on return; attackers leak it (format
  string / OOB read) or use a bug that does not cross it.
- **"What is ROP?"** Return-Oriented Programming: with NX preventing injected
  shellcode, you chain short existing instruction sequences ending in `ret`
  ("gadgets") already in the binary/libc to perform arbitrary computation -
  typically to call `execve("/bin/sh")` or `mprotect` a region executable.
  `ROPgadget`/`ropper` find gadgets; pwntools' `ROP` builds the chain.
- **"ret2libc vs full ROP?"** ret2libc is the simplest ROP: redirect execution
  to an existing libc function (`system`) with a controlled argument. Full ROP
  chains many gadgets for arbitrary logic when a single call is not enough.
- **"What is a GOT/PLT overwrite?"** The GOT holds resolved addresses of
  dynamically-linked functions; an arbitrary write (e.g. via format string)
  into a GOT entry redirects a later call (`printf` -> `system`). Full RELRO
  makes the GOT read-only to prevent this.
- **"How do you find the overflow offset?"** Send a cyclic/De Bruijn pattern
  (`cyclic`/`pattern_create`), observe which 4/8 bytes land in the saved return
  address (`$rip`/`$eip` at the crash), and look it up (`pattern_offset`).

## 5. Quick checklist
- [ ] Identify format (PE/ELF/Mach-O), arch, and protections (`checksec`)
- [ ] Static triage: strings, imports, decompile key functions
- [ ] Dynamic: run in a sandbox/debugger, watch input handling
- [ ] Locate memory-corruption sinks (unbounded copies, format strings, frees)
- [ ] Determine offset / primitive; check ASLR/NX/canary
- [ ] Build leak + control chain (ROP) as needed; PoC safely
- [ ] Report root cause + mitigation (hardening flags, safe APIs)
