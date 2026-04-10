# Capstone: Kernel Rootkit

**Course:** Linux Kernel Security — Spring 2026
**Points:** 100 base + up to 50 bonus
**Due:** See Gradescope

Read `COLDSPARK.md` for the mission and what you need to deliver.
Read `RUBRIC.md` for the exact point breakdown.

---

## What you build

| Directory | What | Required |
|-----------|------|----------|
| `lkm/src/` | Kernel rootkit module | Yes |
| `exploit/` | LPE exploit(s) | Yes |
| `shellcode/` | Beachhead AArch64 shellcode | Yes |
| `loader/` | Reflective module loader | Yes |
| `writeup/README.md` | Design writeup | Yes |

---

## Architecture

```
  Your Machine
  +-------------------------------------------------+
  |  lkm/src/       <- rootkit (you write this)     |
  |  exploit/       <- LPE exploit (you write this) |
  |  shellcode/     <- beachhead (you write this)   |
  |  loader/        <- reflective loader (you write)|
  |  tools/         <- mykill, rkcmd (provided)     |
  |                                                  |
  |  make && make deploy -> shared/capstone/         |
  +-------------------+-----------------------------+
                      | 9P shared folder
  +-------------------v-----------------------------+
  |  Target VM (AArch64, kernel 6.6, no KASLR)      |
  |                                                  |
  |  MERIDIAN service       port 1337                |
  |  /dev/vuln_rwx          RWX kernel shellcode     |
  |  /dev/vuln_rw           arbitrary kernel R/W     |
  |  /home/director/classified/   the target files   |
  +-------------------------------------------------+
```

---

## Rootkit features

All rootkit code lives in `lkm/src/`. It compiles to a single `rootkit.ko`.
The stub files have comments pointing to the relevant homework for each feature.

### File hiding — `file_hide.c`
`/tmp/secret` and `/dev/shm/secret` must not appear in directory listings.
Operator (GID 1337) sees everything.

### Path protection — `rootkit.c`
Opens of `/tmp/secret/*` and `/dev/shm/secret/*` must fail, including
traversal paths like `../../../tmp/secret/flag.txt`.
Operator bypass applies.

### Process hiding — `proc_hide.c`
Processes marked with GID 1337 must be invisible to `ps`, `top`, `ls /proc`.
`mykill add-gid <pid>` marks a process. Operator sees all.

### Module self-hiding — `rootkit.c`
`lsmod` and `/proc/modules` must not list your module after load.
`rmmod rootkit` must still work.

### Covert C2 — `c2.c`
Signal 62 protocol via `mykill`. The command table is in `rootkit.h`.
`rkcmd` / `kill -62 N` works for basic toggles; `mykill` for extended args.

| x0 | Command | x2 |
|----|---------|----|
| 0 | Status | — |
| 1 | Toggle file hiding | — |
| 2 | Toggle access blocking | — |
| 3 | Toggle module visibility | — |
| 4 | Toggle process hiding | — |
| 5 | Add PID to GID 1337 group | target pid |
| 6 | Inject shellcode into process | target pid |
| 7 | Reverse shell (not required) | port |

### Shellcode injection — `inject.c`
Inject AArch64 shellcode into a sleeping process via the C2 channel.
On demo day: `mykill inject <pid> instructor_shellcode.bin`.

### Reflective loader — `loader/`
Load `rootkit.ko` without calling `insmod`. Three valid approaches:

1. **`memfd_create` + `finit_module`** — create an anonymous fd, write the
   `.ko` bytes in, call `finit_module(fd, "", 0)`. This is what insmod does.
2. **Raw syscall** — same as above via `syscall(__NR_finit_module, ...)`.
3. **Manual ELF relocation** — parse ELF, allocate kernel memory, apply
   AArch64 relocations, resolve symbols from `System.map`, call init directly.
   Hard. Module never appears in lsmod.

---

## Privilege escalation — `exploit/`

**Undergrad — `/dev/vuln_rwx`:** kernel shellcode via the RWX driver.
`prepare_creds` / `commit_creds` or direct cred zeroing. KASLR is off —
use `System.map` for symbol addresses.

**Grad — `/dev/vuln_rw`:** arbitrary kernel R/W via ioctl. Walk
`init_task.tasks`, find your cred, zero the uid/gid fields.

Both end with `getuid() == 0`.

---

## Beachhead shellcode — `shellcode/`

AArch64 PIC shellcode delivered via the MERIDIAN `submit` command.
Must not crash the service. Gets you a shell as `analyst`.

---

## Injection test shellcode

`tools/inject_test.bin` verifies your injection machinery. It writes
`"INJECTED-1337 pid=<pid> ppid=<ppid>"` to `/tmp/pwned`.

```bash
sleep 300 &
./mykill inject $! tools/inject_test.bin
cat /tmp/pwned
```

On demo day the instructor hands you different bytes. Same workflow.

---

## WireGuard

Live target at `10.10.10.1`. Your instructor gives you `group-NN.conf`.

```bash
sudo cp group-NN.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
nc 10.10.10.1 1337
```

See `wireguard/README.md` for details.

---

## Quickstart

```bash
make setup-kernel    # download kernel headers (or symlink from lab)
make setup-target    # download QCOW2 + Image
make                 # build everything
make run             # boot dev VM with shared folder

# Inside VM:
mount-shared && cd /mnt/shared/capstone
sudo ./loader rootkit.ko
./mykill status
sudo bash test_lkm.sh

# Automated:
make test
```

---

## Submission

Keep your work in a private GitHub repository. **Invite the instructor
before demo day** so the submission can be reviewed:

```
GitHub: Settings → Collaborators → Add people → [instructor username]
```

Your repo must contain: `lkm/src/`, `exploit/`, `shellcode/`, `loader/`,
and `writeup/README.md`. The instructor will clone it and run `make test`.

---

## Key files

| File | Purpose |
|------|---------|
| `lkm/src/rootkit.h` | Defines, command codes, subsystem interfaces |
| `lkm/src/rootkit.c` | ftrace blocking, module hiding, init/exit |
| `lkm/src/file_hide.c` | getdents64 kretprobe, hide "secret" in /tmp /dev/shm |
| `lkm/src/proc_hide.c` | getdents64 kretprobe, /proc by GID 1337 |
| `lkm/src/c2.c` | kill() kprobe, extended x0-x7 protocol |
| `lkm/src/inject.c` | process injection via vm_mmap |
| `tools/mykill.c` | C2 client, inline asm x0-x7 |
| `tools/inject_test.bin` | Test shellcode (writes /tmp/pwned) |
| `drivers/vuln_rwx/` | RWX kernel shellcode driver |
| `drivers/vuln_rw/` | Arbitrary kernel R/W driver |
| `service/meridian.c` | MERIDIAN TCP service |
| `service/snitch/snitch.ko` | SNITCH IDS (prebuilt) |
