#!/bin/bash
# run_tests.sh — End-to-end test runner
#
# Usage: bash test/run_tests.sh
# Or:    make test
#
# Follows the lab's test-module.sh pattern:
#   1. Build + deploy all artifacts to shared/
#   2. Write shared/autorun.sh (test script that runs inside the VM)
#   3. Create a fresh disposable overlay on the golden QCOW2
#   4. Boot QEMU with shared folder (serial console, no daemonize)
#   5. autotest.service picks up autorun.sh, runs it, powers off
#   6. QEMU exits, output is on your terminal
#
# If the module panics the kernel, the timeout kills QEMU.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

TIMEOUT="${TEST_TIMEOUT:-120}"

# --- Config ---
SHARED="$PROJECT_DIR/shared"
BASE_IMAGE="$PROJECT_DIR/target/capstone-target.qcow2"
OVERLAY="$PROJECT_DIR/target/.test-overlay.qcow2"
KERNEL=""
BOOT_LOG="$SHARED/boot.log"

# Find kernel
for candidate in \
    "$PROJECT_DIR/target/Image" \
    "$PROJECT_DIR/kernel/linux-6.6/arch/arm64/boot/Image" \
    "$HOME/teaching/aarch64-linux-qemu-lab/linux-6.6/arch/arm64/boot/Image"; do
    if [ -f "$candidate" ]; then
        KERNEL="$candidate"
        break
    fi
done

if [ -z "$KERNEL" ]; then
    echo "Error: Kernel Image not found. Run 'make setup-target' first."
    exit 1
fi

if [ ! -f "$BASE_IMAGE" ]; then
    echo "Error: Target QCOW2 not found. Run 'make setup-target' first."
    exit 1
fi

# --- Deploy autorun ---
echo ">>> Writing shared/autorun.sh..."
mkdir -p "$SHARED/capstone"

# Copy test harness to shared
cp -f test/test_lkm.sh "$SHARED/capstone/"
cp -f test/test_challenges.sh "$SHARED/capstone/"
cp -f test/test_chain.sh "$SHARED/capstone/"
cp -f tools/send_shellcode.py "$SHARED/capstone/" 2>/dev/null || true

cat > "$SHARED/autorun.sh" << 'AUTORUN'
#!/bin/bash
# Autorun script — executed by autotest.service inside the VM

cd /mnt/shared/capstone

echo "=== Capstone: End-to-End Tests ==="
echo ""

# Run LKM tests (individual subsystem checks)
if [ -f test_lkm.sh ] && [ -f rootkit.ko ]; then
    echo "========================================"
    echo " LKM Rootkit Tests"
    echo "========================================"
    bash test_lkm.sh 2>&1 || true
    echo ""
fi

# Run LPE challenge tests
if [ -f test_challenges.sh ]; then
    echo "========================================"
    echo " LPE Challenge Tests"
    echo "========================================"
    bash test_challenges.sh || true
    echo ""
fi

# Run full attack chain test
if [ -f test_chain.sh ]; then
    echo "========================================"
    echo " COLDSPARK Attack Chain Test"
    echo "========================================"
    bash test_chain.sh || true
fi
AUTORUN
chmod +x "$SHARED/autorun.sh"

# --- Create fresh overlay ---
echo ">>> Creating fresh overlay (golden image untouched)..."
rm -f "$OVERLAY"
cd "$PROJECT_DIR/target"
qemu-img create -f qcow2 -F qcow2 -b "$(basename "$BASE_IMAGE")" "$(basename "$OVERLAY")" > /dev/null 2>&1
cd "$PROJECT_DIR"

# --- Boot + test ---
echo ">>> Booting VM (timeout ${TIMEOUT}s)..."
echo "    autotest.service will run tests and power off."
echo ""

set +e
# Use script(1) to give QEMU a real pty — without it, serial console
# output gets lost when launched through make/timeout/exec chains.
script -qefc "timeout $TIMEOUT qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a57 \
    -m 2G \
    -smp 2 \
    -nographic \
    -kernel '$KERNEL' \
    -drive 'if=none,file=$OVERLAY,format=qcow2,id=hd0' \
    -device 'virtio-blk-device,drive=hd0' \
    -append 'root=/dev/vda rw console=ttyAMA0 nokaslr' \
    -netdev 'user,id=net0,hostfwd=tcp::11337-:1337' \
    -device 'virtio-net-device,netdev=net0' \
    -virtfs 'local,path=$SHARED,mount_tag=hostshare,security_model=mapped,id=hostshare'" \
    "$BOOT_LOG"
QEMU_EXIT=$?
set -e

# --- Summary ---
echo ""
if [ $QEMU_EXIT -eq 124 ]; then
    echo "!!! TIMEOUT: VM did not power off within ${TIMEOUT}s."
    echo "!!! Likely a kernel panic or deadlock."
    EXIT=1
elif [ $QEMU_EXIT -ne 0 ]; then
    echo ">>> QEMU exited with code $QEMU_EXIT"
    EXIT=$QEMU_EXIT
else
    echo ">>> VM powered off. Test cycle complete."
    EXIT=0
fi

# --- Cleanup ---
rm -f "$SHARED/autorun.sh"
rm -f "$OVERLAY"

# Show results file if the guest wrote one
if [ -f "$SHARED/test_results.log" ]; then
    echo ""
    echo "=== Test Results ==="
    cat "$SHARED/test_results.log"
    rm -f "$SHARED/test_results.log"
fi

exit ${EXIT:-0}
