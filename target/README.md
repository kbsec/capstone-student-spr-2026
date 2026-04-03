# Target VM Assets

This directory holds the target VM disk image and kernel.

## Required Files

| File | Size | Source |
|------|------|--------|
| `capstone-target.qcow2` | ~285 MB | Course file server |
| `Image` | ~50 MB | Course file server or lab build |

## Setup

Run from the project root:

```bash
make setup-target
```

Or download manually:

```bash
# From course file server
curl -L <COURSE_URL>/capstone-assets.tar.gz -o /tmp/assets.tar.gz
tar xzf /tmp/assets.tar.gz -C target/

# Or symlink from the lab repo
ln -s ~/teaching/aarch64-linux-qemu-lab/linux-6.6/arch/arm64/boot/Image target/Image
```

## Scripts

- `start-target.sh` — Boot target VM in black-box mode (MERIDIAN on port 11337)
- `start-dev.sh` — Boot dev VM with shared folder + SSH
