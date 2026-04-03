# Capstone: Kernel Rootkit + Exploitation

**Course:** Linux Kernel Security -- Spring 2026
**Architecture:** AArch64 (ARM 64-bit) | **Kernel:** Linux 6.6 (no KASLR)
**Points:** 200 base + up to 90 extra credit

Build a fully functional Linux kernel rootkit, develop privilege escalation exploits, and write AArch64 shellcode -- all targeting a live MERIDIAN DEFENSE GROUP environment running on an AArch64 QEMU VM.

**Read `COLDSPARK.md` first** -- it's your targeting package and sets the mission context. Then read `capstone.md` for the full assignment specification.

---

## Prerequisites

- AArch64 cross-compiler (`aarch64-linux-gnu-gcc`)
- QEMU (`qemu-system-aarch64`)
- GNU Make
- Python 3 (for `send_shellcode.py`)
- WireGuard (for live target access)

---

## Setup

```bash
# Clone and enter the repo
git clone <repo-url> capstone-student
cd capstone-student

# Download kernel headers (needed for building kernel modules)
make setup-kernel

# Download VM disk image and kernel
make setup-target
```

---

## Build

```bash
make            # Build all components
make lkm        # Build rootkit.ko only
make exploit     # Build exploit programs only
make shellcode   # Assemble beachhead shellcode only
make tools       # Build C2 helpers (mykill, rkcmd)
make clean       # Remove all build artifacts
```

---

## Run (Local QEMU)

```bash
make deploy     # Copy built artifacts to QEMU shared folder
make run        # Boot dev VM with shared folder (ephemeral overlay)
make run-persist # Boot dev VM with persistent overlay
```

Inside the VM:

```bash
mount-shared
cd /mnt/shared/capstone
sudo insmod rootkit.ko
./mykill status
```

---

## Test

```bash
make test               # Full automated test suite (boots fresh VM)

# Or run individual test suites inside the VM:
sudo bash test_lkm.sh           # Rootkit module tests
sudo bash test_lkm.sh c2        # Test a specific subsystem
sudo bash test_challenges.sh    # Driver exploit tests
sudo bash test_chain.sh         # Full COLDSPARK attack chain
```

---

## Live Target (WireGuard)

```bash
# Connect to the target network
make wg-up

# Deliver beachhead shellcode
python3 tools/send_shellcode.py shellcode/beachhead.bin 10.10.10.1 1337

# Run the full chain test against the live target
TARGET=10.10.10.1 bash test/test_chain.sh

# Disconnect
make wg-down
```

See `wireguard/README.md` for VPN setup details.

---

## Repository Layout

```
capstone-student/
├── capstone.md          # Full assignment specification
├── COLDSPARK.md         # Threat intel targeting package
├── Makefile             # Top-level build orchestration
├── config.mk            # Cross-compile settings
│
├── lkm/src/             # Kernel rootkit module (YOU WRITE THIS)
│   ├── rootkit.c        #   ftrace blocking, module self-hiding
│   ├── file_hide.c      #   File hiding via getdents64 kretprobe
│   ├── proc_hide.c      #   Process hiding via /proc filtering
│   ├── c2.c             #   Covert C2 via kill() kprobe
│   └── inject.c         #   Userland shellcode injection
│
├── exploit/             # Privilege escalation exploits (YOU WRITE THESE)
├── shellcode/           # AArch64 beachhead shellcode (YOU WRITE THIS)
├── loader/              # Reflective ELF loader (OPTIONAL EXTRA CREDIT)
│
├── tools/               # Provided C2 helpers (mykill, rkcmd, send_shellcode.py)
├── drivers/             # Provided vulnerable kernel drivers (vuln_rwx, vuln_rw)
├── service/             # MERIDIAN TCP service + SNITCH IDS
├── test/                # Automated test harnesses
├── target/              # QEMU VM boot scripts and assets
├── wireguard/           # WireGuard VPN configs (50 groups)
├── kernel/              # Kernel headers (linux-6.6)
├── shared/              # QEMU 9P mount point (auto-populated by make deploy)
└── deploy/              # Ansible playbooks for live target
```

---

## What You Implement

| Component | Location | Points |
|-----------|----------|--------|
| File hiding (kretprobe) | `lkm/src/file_hide.c` | 25 |
| Access blocking (ftrace) | `lkm/src/rootkit.c` | 20 |
| Module self-hiding | `lkm/src/rootkit.c` | 10 |
| Covert C2 channel (kprobe) | `lkm/src/c2.c` | 25 |
| Process hiding (kretprobe) | `lkm/src/proc_hide.c` | 20 |
| RWX driver exploitation | `exploit/exploit_rwx.c` | 20 |
| R/W privilege escalation | `exploit/exploit_rw.c` | 25 |
| modprobe_path hijack | `exploit/exploit_modprobe.c` | 30 |
| **Subtotal** | | **175** |
| Beachhead shellcode | `shellcode/beachhead.S` | 25 |
| **Total** | | **200** |

### Extra Credit

| Component | Location | Points |
|-----------|----------|--------|
| Direct kernel module loading | `exploit/` | +40 |
| Reflective module loading | `loader/` | +50 |
| SNITCH IDS evasion | `lkm/src/` | +15 |

---

## Submission

```bash
make submission.zip
```

Upload `submission.zip` to Gradescope.

---

## Useful Make Targets

| Target | Description |
|--------|-------------|
| `make load` | `insmod rootkit.ko` (run inside VM) |
| `make unload` | `rmmod rootkit` (run inside VM) |
| `make reload` | Unload + reload the module |
| `make log` | `dmesg \| tail -40` |
| `make status` | Check if rootkit is loaded and C2 is active |
| `make overlay` | Create a fresh QCOW2 overlay |
| `make clean-overlay` | Delete all overlay images |
