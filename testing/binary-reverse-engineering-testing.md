# Binary Analysis, Reverse Engineering & Exploitation - Practitioner Reference

Companion to the thick-client and network guides. Covers the workflow for
compiled targets with no source: triage, static disassembly/decompilation,
dynamic debugging, finding memory-corruption bugs, and developing an exploit
under modern mitigations. Applies to desktop/native clients, IoT/firmware, CTF
pwn, and malware triage. Do this only in an isolated sandbox for untrusted or
malicious binaries.

> Concepts/interview framing: [../knowledge/binary-reverse-engineering.md](../knowledge/binary-reverse-engineering.md) | native thick-client context: [thick-client-security-testing.md](thick-client-security-testing.md) | full tool inventory: [tools-reference.md](tools-reference.md) | methodology/CVSS/reporting: [sdlc-security-testing.md](sdlc-security-testing.md).

---

## 1. Methodology

1. **Triage** - file type/arch, protections, strings, imports. Decide reversing
   vs exploitation goal.
2. **Static analysis** - disassemble/decompile, map logic, locate interesting
   and dangerous functions.
3. **Dynamic analysis** - run under a debugger in a sandbox; confirm behaviour,
   watch input handling, trace syscalls/API calls.
4. **Vulnerability discovery** - locate memory-corruption sinks; fuzz inputs.
5. **Exploitation** - determine the primitive, defeat mitigations, build a PoC.
6. **Report** - root cause, reproducible PoC, impact, mitigation.

---

## 2. Triage (first 5 minutes)
```bash
file ./target            # format + arch
checksec --file=./target # NX, PIE, canary, RELRO, Fortify
strings -n 6 ./target    # URLs, paths, format strings, creds
nm -D ./target           # dynamic symbols (Linux)
rabin2 -I ./target       # radare2: binary info
```
Protections decide the exploit strategy: no NX -> shellcode; NX -> ROP; no PIE
-> fixed addresses; canary -> need a leak.

## 3. Static analysis
| Tool | Use |
| --- | --- |
| Ghidra | free decompiler + disassembler (NSA), scripting |
| IDA Pro / IDA Free | industry disassembler/decompiler |
| Binary Ninja | modern disassembler, good API |
| radare2 / Cutter | CLI + GUI RE framework |
| objdump / readelf | quick disassembly, headers |

Start at `main`/entry and at the dangerous sinks (`strcpy`, `gets`, `sprintf`,
`memcpy`, `system`, `printf`-family with a non-literal format). Rename and
annotate as you recover logic.

## 4. Dynamic analysis
| Tool | Platform | Use |
| --- | --- | --- |
| gdb + pwndbg/GEF | Linux | debugging, heap/stack inspection, pattern offset |
| x64dbg / WinDbg | Windows | debugging PE |
| ltrace / strace | Linux | library / syscall tracing |
| Frida | cross | runtime hooking/instrumentation |
| QEMU | cross-arch | emulate firmware/other-arch binaries |

Run untrusted binaries in a disposable VM with no network (or a controlled one).
Set breakpoints on input-handling and sink functions; inspect registers and
memory at the crash.

## 5. Vulnerability discovery

### Memory-corruption bug classes (what you are hunting)
- **Stack buffer overflow** - unbounded copy into a fixed stack buffer (`gets`, `strcpy`, `sprintf`, `scanf("%s")`); overwrites the saved return address. The classic control-flow hijack.
- **Heap overflow / use-after-free (UAF) / double-free** - overflow into adjacent heap chunk metadata, or use a pointer after `free`; exploited via heap grooming and allocator metadata (tcache/fastbin) corruption to get an arbitrary write.
- **Format string** - user input used as the format argument (`printf(user)` instead of `printf("%s", user)`): `%x`/`%p` leak the stack (defeat ASLR/canary), `%n` writes to memory.
- **Integer overflow / underflow** - bad size math feeding a copy or allocation (`malloc(n*size)` wrapping), producing an undersized buffer then overflowed.
- **Off-by-one / OOB read-write** - a single-byte or bounds error; OOB reads leak data, OOB writes corrupt state.

### How
- **Manual:** trace user input to unbounded copies, non-literal format strings, `free`/use paths, and integer math feeding allocations (the sinks you flagged in static analysis).
- **Fuzzing:** **AFL++** / libFuzzer with a harness for breadth; triage crashes with ASan (reports the exact corruption type) and a debugger.
- Find the overflow offset with a cyclic pattern (`cyclic` / `pattern_create` -> `pattern_offset`).

## 6. Exploitation under mitigations
- **No NX:** inject shellcode, jump to it.
- **NX on:** ROP - chain existing gadgets (`ROPgadget`, `ropper`); ret2libc to
  call `system("/bin/sh")`.
- **ASLR on:** need an info leak (format string, OOB read) to resolve addresses,
  then build the chain against the leaked base.
- **Canary on:** leak it and replace it, or use a bug that does not cross it.
- Build with **pwntools** (`process`/`remote`, `p64`, `ROP`); verify locally
  before any in-scope remote target.

```python
from pwn import *
io = process('./target')
payload = b'A'*offset + p64(canary) + b'B'*8 + rop_chain
io.sendline(payload); io.interactive()
```

## 7. Tools & checklist
**Static:** Ghidra, IDA, Binary Ninja, radare2/Cutter, objdump/readelf.
**Dynamic:** gdb+pwndbg/GEF, x64dbg/WinDbg, ltrace/strace, Frida, QEMU.
**Exploit/fuzz:** pwntools, ROPgadget/ropper, AFL++, libFuzzer, checksec.
(Full inventory in [tools-reference.md](tools-reference.md).)

**Checklist:**
- [ ] authorization + isolated sandbox
- [ ] file/arch/protections (checksec)
- [ ] strings + imports triage
- [ ] static decompile of key + sink functions
- [ ] dynamic run + input tracing
- [ ] memory-corruption sink located / fuzzed
- [ ] offset + primitive determined
- [ ] mitigations assessed (NX/ASLR/canary)
- [ ] leak + control chain PoC
- [ ] root cause + hardening recommendation.

## Quick mental model
Triage tells you the rules (which protections are on). Static finds the bug,
dynamic confirms it, and the exploit chains a leak with a control primitive to
win within those rules.
