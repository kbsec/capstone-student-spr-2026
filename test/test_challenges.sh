#!/bin/bash
# test_challenges.sh — Automated tests for LPE challenges
#
# Tests the vulnerable driver challenges. Must be run as root inside the
# QEMU VM with the drivers loaded.
#
# Usage:
#   sudo bash test/test_challenges.sh

set -e

PASS=0
FAIL=0
SKIP=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP + 1)); }

# Get the capstone directory
CAPSTONE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "========================================"
echo " Capstone Challenge Tests"
echo "========================================"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

# ── Check drivers ────────────────────────────────────────────────────────────

echo "── Checking drivers ──"
echo ""

if [ -c /dev/vuln_rwx ]; then
    pass "/dev/vuln_rwx exists"
else
    skip "/dev/vuln_rwx not found — load driver first"
fi

if [ -c /dev/vuln_rw ]; then
    pass "/dev/vuln_rw exists"
else
    skip "/dev/vuln_rw not found — load driver first"
fi

# ── Check exploits ───────────────────────────────────────────────────────────

echo ""
echo "── Checking exploits ──"
echo ""

for exploit in exploit_rwx exploit_privesc exploit_modprobe; do
    EXPLOIT_PATH="$CAPSTONE_DIR/exploit/$exploit"
    if [ -x "$EXPLOIT_PATH" ]; then
        pass "$exploit built"

        echo "  Running $exploit..."
        if "$EXPLOIT_PATH" 2>&1 | grep -q "SUCCESS: uid=0"; then
            pass "$exploit achieved root"
        elif "$EXPLOIT_PATH" 2>&1 | grep -q "not implemented"; then
            skip "$exploit not yet implemented (stub)"
        else
            fail "$exploit did not achieve root"
        fi
    else
        skip "$exploit not built (add to exploit/Makefile)"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "========================================"
echo " Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
