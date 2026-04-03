# Capstone: Kernel Rootkit + Exploitation

**Course:** Linux Kernel Security — Spring 2026
**Due:** See Gradescope for deadline
**Points:** 200 base + up to 90 extra credit

---

## Overview

You will build a fully functional Linux kernel rootkit, develop privilege escalation exploits, and write AArch64 shellcode — all targeting a live MERIDIAN DEFENSE GROUP environment running on an AArch64 QEMU VM.

This is a **kernel-only** assignment. There is no userland (LD_PRELOAD) component.

**Read `COLDSPARK.md` first** — it's your targeting package and sets the mission context.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Your Development Host                                           │
│                                                                  │
│  capstone-student/                                               │
│  ├── lkm/src/       ← rootkit module (you write this)           │
│  ├── exploit/        ← LPE exploits (you write these)           │
│  ├── shellcode/      ← beachhead shellcode (you write this)     │
│  ├── loader/         ← reflective loader (optional, you write)  │
│  └── tools/          ← mykill, rkcmd (provided)                 │
│                                                                  │
│  make && make deploy → shared/capstone/                          │
└──────────────────┬───────────────────────────────────────────────┘
                   │ 9P shared folder
┌──────────────────▼───────────────────────────────────────────────┐
│  Target VM (AArch64, kernel 6.6, no KASLR)                       │
│                                                                  │
│  mount-shared → /mnt/shared/capstone/                            │
│  insmod rootkit.ko                                               │
│  ./mykill status | hide-files | inject | ...                     │
│                                                                  │
│  MERIDIAN service on port 1337 (analyst user)                    │
│  /dev/vuln_rwx, /dev/vuln_rw (vulnerable drivers)               │
│  /home/director/classified/ (intelligence targets)               │
└──────────────────────────────────────────────────────────────────┘
```

---

## Part B: Kernel Rootkit (100 points)

All code goes in `lkm/src/`. The module compiles as a single `rootkit.ko`.

### B1: File Hiding — 25 points
**File:** `file_hide.c`

Hook `__arm64_sys_getdents64` via kretprobe. Filter directory entries whose `d_name` starts with `HIDDEN_PREFIX` (`"rk_"`).

- **Entry handler:** save userspace buffer pointer (dirp) from the double-indirection pt_regs
- **Return handler:** copy dirent buffer to kernel, walk entries, memmove to remove matches, copy back, adjust return value

**Tests:**
- `ls /tmp` does not show `rk_*` files
- `cat /tmp/rk_test` still works (file exists, just invisible in listings)
- Non-hidden files unaffected

### B2: Access Blocking — 20 points
**File:** `rootkit.c`

Hook `do_sys_openat2` via ftrace. Block access to hidden directories (`/tmp/secret` and `/dev/shm/secret`) by zeroing the filename pointer (causes -EFAULT). These directories are used as dead drops and staging areas — the rootkit prevents non-operator users from discovering them.

- Use kprobe-based symbol lookup trick to resolve `do_sys_openat2`
- Register ftrace with `FTRACE_OPS_FL_IPMODIFY`
- Use prefix matching: block any path starting with `HIDDEN_DIR_1` or `HIDDEN_DIR_2`
- Note: `do_sys_openat2` is NOT a `__arm64_sys_*` wrapper — no double pt_regs

**Tests:**
- `cat /tmp/secret/flag.txt` fails with -EFAULT
- `cat /dev/shm/secret/flag.txt` fails with -EFAULT
- `ls /tmp/secret/` fails
- `/tmp/normal_file.txt` and other paths unaffected
- Blocked access logged in dmesg

### B3: Module Self-Hiding — 10 points
**File:** `rootkit.c`

Remove the module from the kernel's module list via `list_del_init()`.

- Save `THIS_MODULE->list.prev` before removal
- Module disappears from `lsmod` and `/proc/modules`
- `rmmod rootkit` still works (hash table, not list)
- `/sys/module/rootkit/` still exists (kobject — known limitation)

### B4: Covert C2 Channel — 25 points
**File:** `c2.c`

Hook `__arm64_sys_kill` via kprobe. When `signal == MAGIC_SIGNAL (62)`, interpret the call as a rootkit command.

**Basic commands (via `rkcmd` or `kill -62`):**
| x0 (command) | Action |
|---|---|
| 0 | Status — log current state |
| 1 | Toggle file hiding |
| 2 | Toggle access blocking |
| 3 | Toggle module visibility |
| 4 | Toggle process hiding |

**Extended commands (via `mykill` — preserves x2-x7):**
| x0 | x2 | Action |
|---|---|---|
| 5 | — | Add path to hide list (path in `/dev/shm/rk_cmd`) |
| 6 | pid | Add PID's process to GID 1337 group |
| 7 | pid | Inject shellcode into target PID |
| 8 | port | Spawn reverse shell (IP in x3) |

**Key points:**
- Swallow intercepted kills by rewriting to `kill(self, 0)`
- Use deferred workqueue for CMD_INJECT (can't call blocking APIs from kprobe)
- Read bulk data from `/dev/shm/rk_cmd` via `kernel_read()`

**Tests:**
- `mykill status` works, regular kill unaffected
- Toggle commands enable/disable features
- Non-magic signals pass through

### B5: Process Hiding — NEW — 20 points
**File:** `proc_hide.c`

Hook `__arm64_sys_getdents64` via a SEPARATE kretprobe. Filter `/proc` entries for processes with GID 1337.

- **Entry handler:** check if fd's dentry is `/proc` (via `file_dentry()->d_iname`), save dirp
- **Return handler:** for each numeric dirent, `find_task_by_vpid()`, check if task's `group_info` contains GID 1337 → remove entry
- **GID 1337 bypass:** if the CALLING process has GID 1337 (`in_group_p`), skip all filtering — operator sees everything
- **C2 integration:** `mykill add-gid <pid>` adds GID 1337 to a process's supplementary groups

**Tests:**
- Start `sleep`, `mykill add-gid <pid>`, verify `ls /proc` doesn't list it
- `kill -0 <pid>` still works (process exists, just hidden from listing)

---

## Part D: Challenges (variable points)

### Challenge 7: RWX Kernel Shellcode — 20 points
Exploit `/dev/vuln_rwx` to execute kernel shellcode that calls `prepare_creds()` → `commit_creds()` for root.

### Challenge 8: Arbitrary R/W Privilege Escalation — 25 points
Exploit `/dev/vuln_rw` to walk `init_task.tasks`, find your process, zero cred UIDs.

### Challenge 9: modprobe_path Hijack — 30 points
Exploit `/dev/vuln_rw` to overwrite `modprobe_path`, trigger via binary format handler, load rootkit.ko as root without the process ever escalating.

### Challenge 10: Direct Kernel Module Loading — 40 extra credit
Call `load_module()` directly from kernel shellcode via `/dev/vuln_rwx`.

### Challenge 10b: Reflective Module Loading — 50 extra credit
Parse ELF, apply AArch64 relocations, link sections manually in kernel memory. Module never appears in `lsmod`.

### Challenge 11: SNITCH Evasion — 15 extra credit

The target environment includes **SNITCH**, a kernel-resident IDS module with 8 real-time detectors. It is loaded by `setup_capstone.sh` and monitors for:

| Detector | What it watches |
|----------|----------------|
| kprobe on `__arm64_sys_kill` | Signal 62 C2 channel |
| kprobe on `__arm64_sys_memfd_create` | Fileless execution |
| kprobe on `commit_creds` | Privilege escalation |
| kprobe on `__arm64_sys_finit_module` | Module loading |
| kprobe on `register_ftrace_function` | Ftrace hook installation |
| kprobe on `kthread_use_mm` | Kernel→userland code injection |
| Periodic scan | Hidden modules (sysfs/list divergence) |
| Periodic scan | Unauthorized kprobe hooks |

Alerts go to `dmesg` and the `/dev/snitch` ring buffer. The `snitch_watcher` userland daemon reads `/dev/snitch` and logs alerts.

**Baseline approach:** `rmmod snitch` after gaining root. This earns partial credit.

**Full credit:** Complete the COLDSPARK attack chain (beachhead → LPE → rootkit deploy → C2 → exfil) **without unloading SNITCH** and without triggering any alerts. This requires creative evasion — study what SNITCH monitors and find gaps in its coverage.

SNITCH binaries are in `service/snitch/`:
- `snitch.ko` — kernel IDS module (pre-compiled)
- `snitch_watcher` — userland alert daemon
- `snitch-watcher.service` — systemd unit

To test locally with SNITCH enabled, edit `setup_capstone.sh` and set `ENABLE_SNITCH=true`.

---

## Part E: Beachhead Shellcode

Write AArch64 PIC shellcode that achieves initial code execution via the MERIDIAN service's `submit` command. This is Stage 1 of the COLDSPARK attack chain.

---

## Injection Test Shellcode

A pre-built `tools/inject_test.bin` is provided to verify your injection machinery (B5/C2 CMD_INJECT). It writes `"INJECTED-1337 pid=<pid> ppid=<ppid>"` to `/tmp/pwned`. Source is in `tools/inject_test.S`.

Usage:
```bash
# In the VM, with rootkit loaded:
sleep 300 &
./mykill inject $!
cat /tmp/pwned
# Should show: INJECTED-1337 pid=... ppid=...
```

---

## WireGuard VPN

The live MERIDIAN target is accessible over a WireGuard VPN. Your instructor will provide a `group-NN.conf` file with your group's private key.

**Network:**
| Host | IP |
|------|----|
| MERIDIAN target | `10.10.10.1` |
| Your group | `10.10.10.X` (assigned) |

**Setup:**
```bash
sudo cp group-NN.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
ping 10.10.10.1          # verify connectivity
nc 10.10.10.1 1337       # connect to MERIDIAN
```

**Shellcode delivery over WireGuard:**
```bash
python3 tools/send_shellcode.py shellcode/beachhead.bin 10.10.10.1 1337
```

**Test chain over WireGuard:**
```bash
# From your attack host (not inside the VM):
TARGET=10.10.10.1 bash test/test_chain.sh beachhead
```

See `wireguard/README.md` for details and troubleshooting.

---

## Quickstart

### Local development (QEMU VM on your machine)

```bash
# 1. Clone and setup
git clone <repo-url> capstone-student
cd capstone-student
make setup-kernel    # download kernel headers
make setup-target    # download QCOW2 + Image

# 2. Build
make                 # builds lkm, tools (exploit/shellcode when ready)

# 3. Deploy and test
make deploy          # copies to shared/
make run             # boots dev VM with shared folder

# In VM:
mount-shared
cd /mnt/shared/capstone
sudo insmod rootkit.ko
./mykill status
sudo bash test_lkm.sh

# 4. Automated testing
make test            # full test suite
```

### Live target (over WireGuard)

```bash
# 1. Connect VPN
sudo wg-quick up wg0

# 2. Deliver beachhead
python3 tools/send_shellcode.py shellcode/beachhead.bin 10.10.10.1 1337

# 3. Test chain
TARGET=10.10.10.1 bash test/test_chain.sh
```

---

## Submission

```bash
make submission.zip
```

Upload `submission.zip` to Gradescope. Include:
- `lkm/src/` — all rootkit source files
- `exploit/` — all exploit source and binaries
- `shellcode/` — beachhead assembly
- `loader/` — reflective loader (if attempted)

Also submit PIR flag strings from COLDSPARK to the separate Gradescope assignment.

---

## Rubric Summary

| Component | Points |
|-----------|--------|
| B1: File hiding (kretprobe) | 25 |
| B2: Access blocking (ftrace) | 20 |
| B3: Module self-hiding | 10 |
| B4: Covert C2 (kprobe + extended protocol) | 25 |
| B5: Process hiding (GID 1337) | 20 |
| Challenge 7: RWX exploitation | 20 |
| Challenge 8: R/W privilege escalation | 25 |
| Challenge 9: modprobe_path hijack | 30 |
| Challenge 10: Direct kernel module loading | +40 |
| Challenge 10b: Reflective module loading | +50 |
| Challenge 11: SNITCH evasion | +15 |
| **Total** | **200 + 105 EC** |

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `lkm/src/rootkit.h` | All defines, command codes, interfaces |
| `lkm/src/rootkit.c` | ftrace blocking, module hiding, init/exit |
| `lkm/src/file_hide.c` | getdents64 kretprobe for rk_ prefix |
| `lkm/src/proc_hide.c` | getdents64 kretprobe for /proc by GID 1337 |
| `lkm/src/c2.c` | kill() kprobe with extended protocol |
| `lkm/src/inject.c` | process injection via vm_mmap |
| `tools/mykill.c` | Extended C2 binary (x0-x7 via inline asm) |
| `tools/rkcmd.c` | Simple C2 wrapper (backward compat) |
| `tools/inject_test.bin` | Pre-built injection test shellcode |
| `drivers/vuln_rwx/` | RWX kernel shellcode driver (reference) |
| `drivers/vuln_rw/` | Arbitrary R/W driver (reference) |
| `service/meridian.c` | MERIDIAN TCP service (reference) |
| `service/snitch/snitch.ko` | SNITCH IDS kernel module (pre-compiled) |
| `service/snitch/snitch_watcher` | SNITCH userland alert daemon |
