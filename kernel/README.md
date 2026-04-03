# Kernel Headers

This directory holds the Linux 6.6 kernel headers needed for out-of-tree module compilation.

## Setup

Run from the project root:

```bash
make setup-kernel
```

Or set up manually:

```bash
# Option 1: Download headers tarball from course file server
curl -L <COURSE_URL>/linux-6.6-headers.tar.gz -o /tmp/headers.tar.gz
tar xzf /tmp/headers.tar.gz -C kernel/

# Option 2: Symlink from your lab repo
ln -s ~/teaching/aarch64-linux-qemu-lab/linux-6.6 kernel/linux-6.6
```

After setup, you should have `kernel/linux-6.6/Makefile`.

## Building Modules

The `lkm/Makefile` uses `KDIR` from `config.mk`, which defaults to `kernel/linux-6.6/`.
You can override it:

```bash
make KDIR=/path/to/other/kernel lkm
```
