# Capstone Integration Map

How each rootkit feature builds on a prior homework. The capstone is the
integration test — every technique from the semester converges into one
end-to-end attack chain.

---

## Feature → Homework Map

| Capstone file | Feature | Homework |
|---------------|---------|----------|
| `lkm/src/file_hide.c` | Hide `secret/` from `/tmp` and `/dev/shm` | `aarch64-linux-kernel-hooks-kprobe` (cloak) |
| `lkm/src/proc_hide.c` | Hide GID-1337 processes from `/proc` | `aarch64-linux-kernel-hooks-kprobe` (cloak, extended) |
| `lkm/src/rootkit.c` (blocking) | Block `openat` on hidden dirs | `aarch64-linux-kernel-hooks-ftrace` (bouncer) |
| `lkm/src/rootkit.c` (module hide) | Hide from `lsmod` / `/proc/modules` | Lab module: `ghostmod` |
| `lkm/src/c2.c` | Covert C2 via `kill()` | `aarch64-linux-kernel-hooks-kprobe`, HW4 Part 2 |
| `lkm/src/inject.c` | Shellcode injection into sleeping process | `aarch64-kernel-injection` (Parts 1 & 2) |
| `tools/inject_test.S` | AArch64 PIC shellcode, `/tmp/pwned` | `aarch64-kernel-injection` (Part 1 payload) |
| `loader/` | Reflective module loader | `aarch64-reflective-memfd` |
| `exploit/exploit_*.c` | LPE via `/dev/vuln_*` | (new material) |

---

## How Concepts Layer

```
HW: aarch64-linux-kernel-hooks-kprobe
    └── kretprobe on getdents64
            |
HW: aarch64-linux-kernel-hooks-ftrace
    └── ftrace on openat
            |
HW: aarch64-linux-kernel-hooks-syscallhook
    └── syscall table patch
            |
HW: aarch64-kernel-injection
    └── vm_mmap + PC hijack
            |
HW: aarch64-reflective-memfd
    └── memfd + reflective dlopen
            |
HW: aarch64-loader-aux
    └── ELF parsing + bootstrap
            |
CAPSTONE: lkm/src/ + exploit/ + loader/ + shellcode/
    └── all of the above, integrated into one attack chain
```

---

## What Each Homework Contributes

### `aarch64-linux-kernel-hooks-kprobe` → `file_hide.c`, `proc_hide.c`, `c2.c`

Students have already written a kretprobe entry handler that saves `dirp`
from double pt_regs, and a return handler that walks `linux_dirent64`
records and removes entries by name. The capstone uses this pattern in two
places: `file_hide.c` (remove `secret` from `/tmp` and `/dev/shm`) and
`proc_hide.c` (remove numeric PIDs from `/proc`).

The capstone version uses `d_path()` instead of `d_iname()` to identify
the directory being listed, because `/dev/shm` and `/proc` are mount points.

### `aarch64-linux-kernel-hooks-ftrace` → `rootkit.c` (blocking)

Students have already written an ftrace callback that uses
`ftrace_regs_get_argument()` to pull syscall args and zeroes the filename
pointer to cause `-EFAULT`. `blocking_init()` in `rootkit.c` follows the
same pattern. The new wrinkle is handling traversal paths
(`../../../../tmp/secret`) rather than exact prefix matches.

### `ghostmod` lab module → `rootkit.c` (module hiding)

The module hiding pattern (`list_del_init`, save `->prev`, restore with
`list_add`) is directly from the ghostmod lab.

### `aarch64-linux-kernel-hooks-kprobe` + HW4 → `c2.c`

C2 uses a kprobe on `__arm64_sys_kill`. The double pt_regs indirection
(`regs->regs[0]` → user `pt_regs`) is the same pattern from HW4 Part 2.

### `aarch64-kernel-injection` → `inject.c`

`inject.c` is essentially a stripped-down version of the kinject homework.
Students have already written the workqueue trick, `kthread_use_mm`, `vm_mmap`
for an RWX page, `task_pt_regs` PC redirect, and `wake_up_process`.

### `aarch64-reflective-memfd` → `loader/`

The reflective loader homework used `memfd_create` + dlopen-style loading
for a userland `.so`. The capstone applies the same idea to a kernel module.

---

## What's New

These pieces have no direct homework precursor:

| Feature | Why it's new |
|---------|--------------|
| `mykill` extended C2 | Inline asm `svc #0` with x0-x7 pinned — using a syscall as a multi-argument RPC by bypassing libc entirely |
| GID 1337 operator bypass | The homework's `in_group_p()` fails for root; the capstone walks `cred->group_info` directly |
| Multi-file module | Six subsystems wired together in one `rootkit_init()` |
| End-to-end chain | Beachhead → LPE → rootkit → C2 → exfil, all connected |

---

## Test Mapping

| Test group | Mirrors | What it checks |
|------------|---------|----------------|
| `file_hide` | guardian_kprobe Part 3 | `secret` hidden from listings |
| `access_block` | guardian_ftrace Part 2 | openat blocked, traversal blocked |
| `module_hide` | ghostmod | not in lsmod or /proc/modules |
| `c2` | (new) | toggle commands work, non-magic kills pass through |
| `proc_hide` | (new, builds on guardian_kprobe) | GID 1337 hides PID, `kill -0` still works |
| `inject` | kinject Part 1 | shellcode runs, `/tmp/pwned` created |

---

## If You're Stuck

| Stuck on | Re-read |
|----------|---------|
| `file_hide.c` or `proc_hide.c` | `aarch64-linux-kernel-hooks-kprobe` — cloak_kp.c |
| access blocking in `rootkit.c` | `aarch64-linux-kernel-hooks-ftrace` — bouncer_ft.c |
| module hiding in `rootkit.c` | `ghostmod` lab module |
| `c2.c` | `aarch64-linux-kernel-hooks-kprobe` + HW4 Part 2 |
| `inject.c` | `aarch64-kernel-injection` — kinject.c Part 1 |
| `loader/` | `aarch64-reflective-memfd` — loader.c |

The capstone is not asking you to invent new techniques — it's asking you
to take six things you've already built and make them work together against
a live target with active defenses.
