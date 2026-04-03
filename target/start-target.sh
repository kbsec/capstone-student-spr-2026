#!/bin/bash
# ==============================================================================
# Capstone Target VM — Black-Box Mode
# ==============================================================================
#
# Boots the MERIDIAN DEFENSE GROUP target environment with a DISPOSABLE
# overlay. The golden QCOW2 is never modified — every boot is clean.
#
# Prerequisites:
#   - QEMU installed (qemu-system-aarch64)
#   - target/Image and target/capstone-target.qcow2
#
# Usage:
#   ./target/start-target.sh [--kernel PATH] [--persist]
#
# Port forwarding:
#   Host 11337 → Guest 1337 (MERIDIAN service)
#
# Connect:
#   nc localhost 11337
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Defaults ---
KERNEL=""
BASE_IMAGE="$SCRIPT_DIR/capstone-target.qcow2"
OVERLAY="$SCRIPT_DIR/.target-overlay.qcow2"
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
            echo "Connect: nc localhost 11337"
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
            "$HOME/teaching/aarch64-linux-qemu-lab/linux-6.6/arch/arm64/boot/Image" \
            "../kernel/linux-6.6/arch/arm64/boot/Image"; do
            if [ -f "$candidate" ]; then
                KERNEL="$candidate"
                break
            fi
        done
    fi
fi

if [ -z "$KERNEL" ] || [ ! -f "$KERNEL" ]; then
    echo "Error: Kernel Image not found."
    echo ""
    echo "Option 1: Run 'make setup-target' to download assets"
    echo "Option 2: Place Image in target/ directory"
    echo "Option 3: Specify directly: $0 --kernel /path/to/Image"
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

# --- Launch ---
echo "=============================================================================="
echo "  MERIDIAN DEFENSE GROUP — Target Environment"
echo "=============================================================================="
echo ""
echo "  Kernel:     $KERNEL"
echo "  Image:      $OVERLAY (overlay on golden QCOW2)"
echo "  Memory:     $MEMORY"
echo "  Persist:    $([ "$PERSIST" -eq 1 ] && echo "YES" || echo "NO — fresh boot")"
echo ""
echo "  MERIDIAN:   nc localhost 11337"
echo "  Login:      root / root  (via serial console)"
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
    -netdev "user,id=net0,hostfwd=tcp::11337-:1337,hostfwd=udp::51820-:51820" \
    -device "virtio-net-device,netdev=net0"
