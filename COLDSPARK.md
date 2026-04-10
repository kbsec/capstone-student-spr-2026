**🌶️ HEAT LEVEL: 2,200,000 SHU // GHOST PEPPER // EYES SPICY ONLY 🌶️**

---

# TARGETING PACKAGE: MERIDIAN DEFENSE GROUP

**Prepared by:** COLDSPARK Targeting Cell (kitchen table division)
**Date:** Spring 2026
**Distribution:** Course participants and anyone willing to sign the waiver
**Capsaicin Content:** 9.5 / 10 — do not rub eyes after handling

---


## TARGET PROFILE

MERIDIAN DEFENSE GROUP is a totally-legitimate-we-promise private intelligence
contractor that provides "consulting services" to clients who very much
prefer not to be named in writing. They have HUMINT operatives, SIGINT
collection, GEOINT analysts, and at least one guy who just stares at a wall
of monitors all day.

MERIDIAN runs a "Secure Terminal Service" that lets analysts read intel
reports. The terminal is a Linux box (kernel 6.6, AArch64). The sysadmin
left KASLR off because "it was crashing the JIT thing."

That JIT thing is going to be a problem for them.

## KNOWN ATTACK SURFACE

| Vector | What It Is | Why It's Spicy |
|---|---|---|
| Secure Terminal | TCP service on port 1337. Has a `submit` command that takes raw bytes and runs them. The dev who wrote this is not with the company anymore. | 🌶️🌶️🌶️ |
| `/dev/vuln_rwx` | "JIT compilation engine left in production." Allocates RWX kernel memory and runs whatever bytes you send it. Mode 0666 because "the QA team needed access." | 🌶️🌶️🌶️🌶️ |
| `/dev/vuln_rw` | "Debug interface left in production." Arbitrary kernel R/W via ioctl. No bounds checking, no permissions, no remorse. Also mode 0666. | 🌶️🌶️🌶️🌶️ |
| No KASLR | Kernel boots with `nokaslr` because the JIT thing kept segfaulting otherwise. Symbol addresses are stable across boots. `/proc/kallsyms` is root-only but you've got `System.map` from your lab build, which matches. | 🌶️🌶️🌶️ |

## KNOWN DEFENSES

| Defense | What It Does | Heat |
|---|---|---|
| User Separation | Classified files owned by `director` (UID 1002). Mode 0700 directory. Analyst can't read it. You'll need root. | 🌶️ |
| SNITCH | `snitch.ko` — kernel IDS with 8 detectors watching kprobes on `__arm64_sys_kill`, `__arm64_sys_memfd_create`, `commit_creds`, `__arm64_sys_finit_module`, `register_ftrace_function`, `kthread_use_mm`, plus periodic scans for hidden modules and unauthorized hooks. Logs to `dmesg` and `/dev/snitch`. **Easy mode:** `rmmod snitch` after you get root. **Hardcore mode:** complete the chain without unloading it. | 🌶️🌶️🌶️🌶️🌶️ |

## ATTACK CHAIN

```
                    ┌─────────────────────┐
  nc :11337 ───────►│  MERIDIAN Terminal   │
                    │  submit → mmap RWX  │
                    │  clone → exec code  │
                    └────────┬────────────┘
                             │ analyst (uid 1001)
                    ┌────────▼────────────┐
                    │  /dev/vuln_rwx      │  the JIT thing
                    │  /dev/vuln_rw       │  the debug thing
                    └────────┬────────────┘
                             │ root (uid 0)
                    ┌────────▼────────────┐
                    │  load rootkit.ko    │
                    │  (without insmod)   │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │  /home/director/    │
                    │  classified/        │
                    │  (the spicy stuff)  │
                    └─────────────────────┘
```

```
    ┌─────────────┐     ┌──────────────────┐     ┌──────────────┐     ┌──────────────┐
    │   Stage 1   │     │     Stage 2      │     │   Stage 3    │     │   Stage 4    │
    │   Initial   │────>│    Privilege     │────>│   Rootkit    │────>│     C2 +     │
    │   Access    │     │   Escalation     │     │  Deployment  │     │  Exfiltration │
    └─────────────┘     └──────────────────┘     └──────────────┘     └──────────────┘
     nc target:1337      /dev/vuln_rwx or         load rootkit         covert C2
     submit shellcode    /dev/vuln_rw              hide everything     read classified/
     → code exec as      → root                   register hooks      exfil PIRs
       analyst
```

## REQUIRED CAPABILITIES

Establish the following capabilities on the target system, in order.
Each stage depends on the previous one working.

### 1. Initial Access
Achieve code execution on the target via the secure terminal service.
The terminal's `submit` command accepts raw bytes and executes them — send
AArch64 shellcode to run as the `analyst` user.

### 2. Privilege Escalation
Escalate from `analyst` to root via one of the diagnostic drivers.
**Undergrad:** kernel shellcode through `/dev/vuln_rwx` (`prepare_creds` /
`commit_creds` or direct cred zeroing). **Grad:** arbitrary R/W through
`/dev/vuln_rw` (walk `init_task.tasks`, locate own cred, modify uid/gid).
Either path ends with `getuid() == 0`.

### 3. Capability Installation
Deploy a kernel-resident rootkit with the following features:

- **File hiding** — `/tmp/secret` and `/dev/shm/secret` do not appear in
  directory listings (`ls`, `find`, anything calling `getdents64`)
- **Path protection** — opens of `/tmp/secret/*` and `/dev/shm/secret/*` are
  blocked, including traversal: `../../../tmp/secret/flag.txt` must also fail
- **Process hiding** — designated processes are invisible to `ps`, `top`,
  `ls /proc`, anything reading `/proc`
- **Operator bypass** — your operator process can read protected files and see
  hidden processes; non-operator processes remain blocked and blind
- **Covert C2** — kernel and userland communicate without filesystem or network
  artifacts. `mykill` is provided as a reference; use it, modify it, or replace
  it. Must support: status, toggle file hide, toggle access block, toggle process
  hide, mark a PID as operator, trigger injection
- **Code injection** — inject AArch64 PIC shellcode into a sleeping userland
  process via the C2 channel; target survives, shellcode produces its side effect

You must also implement a **reflective loader** — load `rootkit.ko` without
calling `insmod`. `finit_module(memfd_create())`, direct `load_module()`, or
manual ELF relocation all count.

### 4. PSP Subversion (Bonus, +20 pts)
SNITCH monitors for module loading, credential changes, ftrace hooks, and
several other indicators. The baseline approach is `rmmod snitch` once you
have root. The interesting approach is completing the full chain without
tripping a single detector. Partial credit for partial evasion.

### 5. Collection
Exfiltrate the contents of `/home/director/classified/`. Recover all three
Priority Intelligence Requirements listed below and submit them.

## PRIORITY INTELLIGENCE REQUIREMENTS

These are the targets. Each one is a flag string sitting at the end of a
file in `/home/director/classified/`. Get all three.

| PIR | What We Need | Where It Lives | Heat |
|---|---|---|---|
| PIR-ALPHA | Identify the operative deployed to the Horn of Africa region | `agents.txt` | 🌶️🌶️🌶️🌶️🌶️ |
| PIR-BRAVO | Identify the exfiltration plan designator for the Caspian Basin operation | `operation_blackbird.txt` | 🌶️🌶️🌶️🌶️🌶️ |
| PIR-CHARLIE | Recover the ChaCha20 field communication key designator and first 4 hex bytes | `crypto_keys.txt` | 🌶️🌶️🌶️🌶️🌶️ |

Submit the exact flag strings to Gradescope. Format matters — copy them
literally, don't paraphrase.

## TECHNICAL ANNEX

**Connecting to the target:**
```
nc localhost 11337
```
Port 11337 on the host is forwarded to port 1337 on the target VM. (When
the live target comes up, you'll connect over WireGuard to `10.10.10.1:1337`
instead.)

**Target system:**
- Architecture: AArch64 (ARM 64-bit)
- Kernel: Linux 6.6 (no KASLR — see "Known Attack Surface" above for why)
- Boot parameters: `nokaslr`
- `/proc/kallsyms` is root-only — use the `System.map` from your lab kernel
  build (it matches because the kernel binary is identical and KASLR is off)

**Users:**
| User | UID | Role |
|------|----:|---|
| root | 0 | The sysadmin who left the JIT thing in production |
| analyst | 1001 | Runs the MERIDIAN service. This is your beachhead. |
| director | 1002 | Owns the classified files. Never logs in. Never reads the alerts. |

**Key paths:**
| Path | Contents |
|---|---|
| `/dev/vuln_rwx` | The JIT thing |
| `/dev/vuln_rw` | The debug thing |
| `System.map` | Symbol addresses (in your lab build) |
| `/home/director/classified/` | The spicy menu |

---

**🌶️ HEAT LEVEL: 2,200,000 SHU // GHOST PEPPER // EYES SPICY ONLY 🌶️**
**Handle via COLDSPARK channels only.**
