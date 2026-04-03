#!/bin/bash
# ==============================================================================
# Capstone Dev VM — Interactive Development Mode
# ==============================================================================
#
# Boots the target VM with a DISPOSABLE overlay on the golden QCOW2.
# All changes inside the VM are discarded when you shut down.
#
# Features:
#   - 9P shared folder (shared/ → /mnt/shared in guest)
#   - SSH port forwarding (host 10022 → guest 22)
#   - MERIDIAN port forwarding (host 11337 → guest 1337)
#
# Usage:
#   ./target/start-dev.sh [--kernel PATH] [--persist]
#   # or: make run
#
# Options:
#   --persist   Reuse existing overlay instead of creating a fresh one.
#               Useful for iterating without re-running setup_capstone.sh.
#
# Workflow:
#   Host:  make && make deploy
#   Guest: mount-shared && cd /mnt/shared/capstone
#          sudo insmod rootkit.ko
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# --- Defaults ---
KERNEL=""
BASE_IMAGE="$SCRIPT_DIR/capstone-target.qcow2"
OVERLAY="$SCRIPT_DIR/.dev-overlay.qcow2"
SHARED_DIR="$PROJECT_DIR/shared"
MEMORY="2G"
CPUS="2"
PERSIST=0

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)
            KERNEL="$2"
            shift 2
            ;;
        --mem)
            MEMORY="$2"
            shift 2
            ;;
        --persist)
            PERSIST=1
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--kernel PATH] [--mem SIZE] [--persist]"
            echo ""
            echo "  --kernel PATH   Path to aarch64 kernel Image"
            echo "  --mem SIZE      Memory size (default: 2G)"
            echo "  --persist       Reuse overlay (don't create fresh)"
            echo ""
            echo "  SSH:      ssh -p 10022 root@localhost"
            echo "  MERIDIAN: nc localhost 11337"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- Find kernel ---
if [ -z "$KERNEL" ]; then
    if [ -f "$SCRIPT_DIR/Image" ]; then
        KERNEL="$SCRIPT_DIR/Image"
    else
        for candidate in \
            "$PROJECT_DIR/kernel/linux-6.6/arch/arm64/boot/Image" \
            "$HOME/teaching/aarch64-linux-qemu-lab/linux-6.6/arch/arm64/boot/Image"; do
            if [ -f "$candidate" ]; then
                KERNEL="$candidate"
                break
            fi
        done
    fi
fi

if [ -z "$KERNEL" ] || [ ! -f "$KERNEL" ]; then
    echo "Error: Kernel Image not found."
    echo "Run 'make setup-target' or 'make setup-kernel' first."
    exit 1
fi

if [ ! -f "$BASE_IMAGE" ]; then
    echo "Error: Golden image not found at $BASE_IMAGE"
    echo "Run 'make setup-target' to download it."
    exit 1
fi

# --- Create disposable overlay ---
if [ "$PERSIST" -eq 0 ] || [ ! -f "$OVERLAY" ]; then
    echo ">>> Creating fresh overlay on $(basename "$BASE_IMAGE")..."
    rm -f "$OVERLAY"
    qemu-img create -f qcow2 -F qcow2 -b "$(basename "$BASE_IMAGE")" "$OVERLAY" > /dev/null
else
    echo ">>> Reusing existing overlay (--persist)"
fi

# --- Setup shared dir ---
mkdir -p "$SHARED_DIR"

# --- Launch ---
echo "=============================================================================="
echo "  Capstone Dev VM — Interactive Development Mode"
echo "=============================================================================="
echo ""
echo "  Kernel:     $KERNEL"
echo "  Image:      $OVERLAY (overlay on golden QCOW2)"
echo "  Shared:     $SHARED_DIR → /mnt/shared (run 'mount-shared' in guest)"
echo "  Memory:     $MEMORY"
echo "  Persist:    $([ "$PERSIST" -eq 1 ] && echo "YES — overlay kept" || echo "NO — fresh boot")"
echo ""
echo "  SSH:        ssh -p 10022 root@localhost"
echo "  MERIDIAN:   nc localhost 11337"
echo "  Login:      root / root"
echo ""
echo "  Exit QEMU:  Ctrl-a x"
echo "=============================================================================="
echo ""

exec qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a57 \
    -m "$MEMORY" \
    -smp "$CPUS" \
    -nographic \
    -kernel "$KERNEL" \
    -drive "if=none,file=$OVERLAY,format=qcow2,id=hd0" \
    -device "virtio-blk-device,drive=hd0" \
    -append "root=/dev/vda rw console=ttyAMA0 nokaslr" \
    -netdev "user,id=net0,hostfwd=tcp::10022-:22,hostfwd=tcp::11337-:1337,hostfwd=udp::51820-:51820" \
    -device "virtio-net-device,netdev=net0" \
    -virtfs "local,path=$SHARED_DIR,mount_tag=hostshare,security_model=mapped,id=hostshare"
