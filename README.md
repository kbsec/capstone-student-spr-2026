# Capstone: Kernel Rootkit

You're building a kernel rootkit, deploying it against a live target, and evading an IDS that's trying to catch you. Start by reading `COLDSPARK.md` for the scenario, then `capstone.md` for the technical spec.

## Quick start

1. Download the target assets (Image + QCOW2) from **[TODO: course link]** and drop them in `target-package/`
2. Boot the target: `cd target-package && ./start-target.sh`
3. Connect: `nc localhost 11337`

You should see the MERIDIAN secure terminal. Type `help`.

## Prerequisites

You need QEMU and the ARM64 cross-compiler:

```bash
sudo apt install qemu-system-arm gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
```

## Building kernel headers

Your rootkit compiles against Linux 6.6.0 kernel headers. You don't need to build the full kernel, just prepare the headers (takes about a minute):

```bash
cd kernel
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
tar xf linux-6.6.tar.xz
cp dot-config linux-6.6/.config
cd linux-6.6
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare
```

If you already have `aarch64-linux-qemu-lab` set up from earlier in the course, you can skip this and point at your existing kernel build instead: `make lkm KDIR=~/teaching/aarch64-linux-qemu-lab/linux-6.6`. See `kernel/README.md` for more options.

## Build system

The repo is split into subdirectories, each with its own Makefile. The top-level Makefile just calls `make -C <dir>` for each one. You write code in three places:

| Directory | What you build | Top-level target | How it works |
|-----------|---------------|-----------------|--------------|
| `shellcode/` | Beachhead PIC payload | `make shellcode` | `as` + `objcopy` turns your `.S` into a raw `.bin` |
| `lkm/` | Kernel rootkit module | `make lkm` | Linux kbuild compiles your `.c` files into `rootkit.ko` |
| `exploit/` | Privesc programs | `make exploits` | `aarch64-linux-gnu-gcc` cross-compiles your `.c` into static binaries |

Run `make` at the top level to build everything, or `cd` into any directory and run `make` there to build just that component.

### Where to put your code

**Shellcode** (`shellcode/`): Edit `beachhead.S` with your AArch64 assembly. This is the PIC payload you send to the MERIDIAN service over the network. If you need multiple shellcode files, add more `.S` files and list them in `SOURCES` in the Makefile:

```makefile
SOURCES := beachhead.S stage2.S privesc.S
```

Each `.S` file produces a corresponding `.bin`.

**Rootkit** (`lkm/`): The starter code has four source files in `lkm/src/` with TODO stubs where your implementation goes. The Makefile already knows about all four files. If you need to add a new source file, say `lkm/src/keylogger.c`, add it to `rootkit-objs` in `lkm/Makefile`:

```makefile
rootkit-objs := src/rootkit.o \
                src/file_hide.o \
                src/c2.o \
                src/inject.o \
                src/keylogger.o
```

That's it. kbuild handles the rest. Your new file will be compiled and linked into `rootkit.ko` on the next `make lkm`.

**Exploits** (`exploit/`): Each `.c` file is a standalone program. The stubs have scaffolding (ioctl wrappers, symbol lookup) but the actual exploit logic is yours to write. To add a new exploit, add a target to `exploit/Makefile`:

```makefile
TARGETS := exploit_rwx exploit_privesc exploit_modprobe my_new_exploit

my_new_exploit: my_new_exploit.c
	$(CC) $(CFLAGS) -o $@ $<
```

### Cross-compilation

All Makefiles include `config.mk`, which sets `ARCH=arm64` and `CROSS_COMPILE=aarch64-linux-gnu-`. If your cross-compiler is somewhere else, override it:

```bash
make CROSS_COMPILE=aarch64-none-elf-
```

If your kernel headers are somewhere else:

```bash
make KDIR=/path/to/linux-6.6
```

## Development workflow

The cycle is: edit code on your host, cross-compile, deploy into the VM, test.

```bash
# 1. Edit your code
vim lkm/src/file_hide.c

# 2. Build
make lkm

# 3. Deploy to shared folder
make deploy

# 4. Boot target with shared folder
cd target-package && ./start-target.sh --shared

# 5. In the VM: set up environment (first time only)
mount-shared
sudo bash /mnt/shared/capstone/setup_capstone.sh

# 6. Load and test your rootkit
sudo insmod /mnt/shared/capstone/rootkit.ko

# 7. Unload before reloading
sudo rmmod rootkit
```

Repeat steps 1-2-3-6-7 as you iterate. You only need to run `setup_capstone.sh` once per boot.

For shellcode, there's a shortcut:

```bash
make shellcode              # assemble beachhead.S -> beachhead.bin
make -C shellcode send      # send beachhead.bin to the target
```

## SNITCH IDS

The target has a host IDS called SNITCH watching for exactly the kind of things your rootkit does. It has 8 detectors:

- Hidden modules (periodic sysfs vs. module list scan)
- Unauthorized kprobe hooks (periodic debugfs scan)
- Signal 62 (your C2 channel)
- memfd_create (fileless execution)
- commit_creds escalation to root
- finit_module (module loading)
- register_ftrace_function (ftrace hooking)
- kthread_use_mm (process memory takeover for injection)

You probably want to disable SNITCH while you're getting your rootkit features working, then turn it back on when you're ready to test evasion. Open `service/setup_capstone.sh` and flip the toggle near the top:

```bash
ENABLE_SNITCH=false    # disable while building features
ENABLE_SNITCH=true     # re-enable for evasion testing (Step 4)
```

## Kernel symbol resolution

The target boots with `nokaslr`, so kernel addresses are the same every boot. `/proc/kallsyms` is locked down to root, but you don't need it. Just grep `System.map` from your kernel build:

```bash
grep prepare_kernel_cred kernel/linux-6.6/System.map
grep commit_creds kernel/linux-6.6/System.map
grep init_task kernel/linux-6.6/System.map
```

Hardcode these addresses in your exploit. No randomization, no guessing.

## Test scripts

Run these inside the VM after `make deploy`:

```bash
sudo bash test/test_lkm.sh        # rootkit features (B1-B5)
sudo bash test/test_challenges.sh  # exploit challenges (7-9)
```

## Repo layout

```
COLDSPARK.md          Targeting package (your mission briefing)
capstone.md           Technical specification
config.mk             Cross-compile settings (shared by all Makefiles)
Makefile              Top-level build — delegates to each subdirectory

shellcode/            YOUR beachhead shellcode (PIC, AArch64 assembly)
  beachhead.S         Stage 1 payload sent to MERIDIAN
  Makefile            Assembles .S -> .bin via as + objcopy

lkm/                  YOUR kernel rootkit module
  src/rootkit.c       Main module, ftrace hook, module hiding
  src/file_hide.c     File hiding (getdents64 kretprobe)
  src/c2.c            Covert C2 (kill signal hook)
  src/inject.c        Shellcode injection
  Makefile            Builds rootkit.ko via kbuild

exploit/              YOUR privilege escalation exploits
  exploit_rwx.c       Challenge 7 — /dev/vuln_rwx
  exploit_privesc.c   Challenge 8 — /dev/vuln_rw
  exploit_modprobe.c  Challenge 9 — modprobe_path
  Makefile            Builds all exploit binaries

drivers/              Vulnerable kernel drivers (provided, source included)
service/              MERIDIAN service + SNITCH IDS binaries
  snitch/             Pre-built SNITCH (no source)
tools/                C2 helpers (rkcmd, send_shellcode.py)
test/                 Test suites
target-package/       Target VM (Image + QCOW2)
kernel/               Kernel config for building headers
docs/                 Written analysis template
```

## Submit

Submit the three PIR flag strings to Gradescope. See `COLDSPARK.md` for what you're looking for.
