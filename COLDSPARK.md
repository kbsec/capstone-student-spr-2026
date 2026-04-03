**TOP SECRET // SCI // NOFORN**

---

# TARGETING PACKAGE: MERIDIAN DEFENSE GROUP

**Prepared by:** COLDSPARK Targeting Cell
**Date:** Spring 2026
**Distribution:** Course participants only

---

## TARGET PROFILE

MERIDIAN DEFENSE GROUP is a foreign private intelligence contractor providing
signals intelligence (SIGINT), human intelligence (HUMINT), and geospatial
intelligence (GEOINT) services to hostile state actors. Assessment indicates
MERIDIAN maintains classified source networks, active collection operations,
and cryptographic key material on an internal computing system.

MERIDIAN operates a secure terminal service for analyst-level staff to access
unclassified intelligence reports. The terminal runs on a Linux-based system
(kernel 6.6, AArch64 architecture) with no address space layout randomization
(KASLR disabled).

## KNOWN ATTACK SURFACE

| Vector | Description |
|--------|-------------|
| Secure Terminal | TCP service on port 1337. Accepts "field data submissions" — raw binary upload with no input validation. Runs as unprivileged user `analyst` (UID 1001). |
| Diagnostic Driver (RWX) | `/dev/vuln_rwx` — JIT compilation engine left in production. Allocates executable kernel memory and runs user-supplied bytecode at ring 0. Accessible to all users (mode 0666). |
| Diagnostic Driver (RW) | `/dev/vuln_rw` — Debug interface left in production. Provides arbitrary kernel memory read/write via ioctl. Accessible to all users (mode 0666). |
| No KASLR | Kernel is booted with `nokaslr`. Symbol addresses are fixed across boots and match `System.map` from the kernel build. `/proc/kallsyms` is restricted to root — resolve addresses offline from `System.map` before exploitation. |

## KNOWN DEFENSES

| Defense | Description |
|---------|-------------|
| User Separation | Classified materials owned by `director` (UID 1002), inaccessible to `analyst`. Root required for access. |
| SNITCH (kernel) | `snitch.ko` — Kernel-resident IDS module with 8 detectors: periodic scans for hidden modules (sysfs/list divergence) and unauthorized kprobe hooks; real-time kprobes on `__arm64_sys_kill` (signal 62 C2), `__arm64_sys_memfd_create` (fileless exec), `commit_creds` (privilege escalation), `__arm64_sys_finit_module` (module loading), `register_ftrace_function` (ftrace hook installation), and `kthread_use_mm` (kernel→userland code injection). Alerts to `dmesg` and `/dev/snitch` ring buffer. _Assessment: baseline neutralization via `rmmod snitch` after gaining root. Advanced operators may attempt evasion without unloading._ |

## ATTACK CHAIN

```
                    ┌─────────────────────┐
  nc :11337 ───────►│  MERIDIAN Terminal   │
                    │  submit → mmap RWX  │
                    │  clone → exec code  │
                    └────────┬────────────┘
                             │ analyst (uid 1001)
                    ┌────────▼────────────┐
                    │  /dev/vuln_rwx      │  JIT engine
                    │  /dev/vuln_rw       │  Debug interface
                    └────────┬────────────┘
                             │ root (uid 0)
                    ┌────────▼────────────┐
                    │  insmod rootkit.ko  │
                    │  C2: kill -62 <cmd> │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │  /home/director/    │
                    │  classified/        │
                    │  PIR-ALPHA/BRAVO/   │
                    │  CHARLIE            │
                    └─────────────────────┘
```

```
    ┌─────────────┐     ┌──────────────────┐     ┌──────────────┐     ┌──────────────┐
    │   Stage 1   │     │     Stage 2      │     │   Stage 3    │     │   Stage 4    │
    │   Initial   │────>│    Privilege     │────>│   Rootkit    │────>│     C2 +     │
    │   Access    │     │   Escalation     │     │  Deployment  │     │  Exfiltration │
    └─────────────┘     └──────────────────┘     └──────────────┘     └──────────────┘
     nc target:1337      /dev/vuln_rwx or         insmod rootkit.ko    kill -62 C2
     submit shellcode    /dev/vuln_rw              hide module          read classified/
     → code exec as      → root                   register hooks       exfil data
       analyst
```

## REQUIRED CAPABILITIES

Establish the following capabilities on the target system, in order:

### 1. Beachhead
Achieve initial code execution on the target via the secure terminal service.
The terminal's `submit` command accepts raw bytes and executes them — exploit
this to run AArch64 shellcode as the `analyst` user.

### 2. Privilege Escalation
Escalate from the `analyst` service account to full administrative (root) access.
Use one of the diagnostic kernel drivers to modify process credentials or execute
kernel shellcode.

### 3. Capability Installation
Deploy a persistent kernel-resident implant with the following features:
- **File concealment** — hide files matching a designated prefix from directory listings
- **Access denial** — block access to specified filesystem paths
- **Self-concealment** — hide the implant from kernel module enumeration tools
- **Covert command channel** — accept operator commands via an out-of-band signaling mechanism (no filesystem or network artifacts)
- **Code injection** — inject and execute shellcode in a target userland process

### 4. PSP Subversion
Neutralize the SNITCH host monitoring agent to prevent detection of implant
activity. Baseline approach: unload the SNITCH kernel module after gaining
administrative access.

### 5. Collection
Exfiltrate all materials from the director's classified repository at
`/home/director/classified/`. Recover the Priority Intelligence Requirements
listed below.

## PRIORITY INTELLIGENCE REQUIREMENTS

| PIR | Requirement | Expected Format |
|-----|-------------|-----------------|
| PIR-ALPHA | Identify the operative deployed to the Horn of Africa region | Flag string at end of `agents.txt` |
| PIR-BRAVO | Identify the exfiltration plan designator for the Caspian Basin operation | Flag string at end of `operation_blackbird.txt` |
| PIR-CHARLIE | Recover the ChaCha20 field communication key designator and first 4 hex bytes | Flag string at end of `crypto_keys.txt` |

Submit the exact PIR flag strings to Gradescope.

## TECHNICAL ANNEX

**Connecting to the target:**
```
nc localhost 11337
```
Port 11337 on the host is forwarded to port 1337 on the target VM.

**Target system:**
- Architecture: AArch64 (ARM 64-bit)
- Kernel: Linux 6.6 (no KASLR)
- Boot parameters: `nokaslr`
- `/proc/kallsyms` restricted to root — use `System.map` from your lab kernel build

**Users:**
| User | UID | Role |
|------|-----|------|
| root | 0 | System administrator |
| analyst | 1001 | MERIDIAN service account (your beachhead) |
| director | 1002 | Intelligence director (owns classified files) |

**Key paths:**
| Path | Contents |
|------|----------|
| `/dev/vuln_rwx` | RWX kernel shellcode driver |
| `/dev/vuln_rw` | Arbitrary kernel read/write driver |
| `System.map` | Kernel symbol addresses (in your lab kernel build — same kernel, no KASLR, addresses match) |
| `/home/director/classified/` | Target intelligence (root access required) |

---

**TOP SECRET // SCI // NOFORN**
**Handle via COLDSPARK channels only.**
