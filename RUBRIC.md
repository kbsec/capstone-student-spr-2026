# Capstone Rubric — COLDSPARK

**Total:** 100 points base + up to 50 bonus points

Undergrad and grad have the same total. LPE has separate paths but
both are worth 12 pts.

---

## Base (100 points)

### Attack chain: implementation and integration (78 pts)

**1. Initial access exploit: 8 pts**
Beachhead shellcode delivered via the MERIDIAN `submit` command runs as
`analyst`. Must be PIC AArch64 and must not crash the service.

**2. Local Privilege Escalation: 12 pts**
Escalate from `analyst` to root via `/dev/vuln_*`.
- Undergrad: kernel shellcode via `/dev/vuln_rwx`
  (`prepare_creds`/`commit_creds` or direct cred zeroing)
- Grad: arbitrary R/W via `/dev/vuln_rw`
  (walk `init_task.tasks`, locate cred, modify uid/gid)

**3. Reflective rootkit loader: 10 pts**
Load `rootkit.ko` without calling `insmod`. Any mechanism counts:
`finit_module(memfd_create())`, direct `load_module()`, or manual ELF
relocation.

**4. File hiding: 7 pts**
`/tmp/secret` and `/dev/shm/secret` do not appear in directory listings.
Other entries in those directories are unaffected.

**5. Path protection with traversal handling: 10 pts**
Opens of `/tmp/secret/*` and `/dev/shm/secret/*` are blocked. The block
must hold against traversal: `../../../tmp/secret/flag.txt` and
`/foo/bar/../../tmp/secret/flag.txt` must also fail. Mechanism is your
choice.

**6. Process hiding: 8 pts**
Designated processes are invisible to `ps`, `top`, `ls /proc`, anything
reading `/proc`. Mechanism is your choice.

**7. Operator bypass: 4 pts**
Your operator process can read `/tmp/secret/*` and `/dev/shm/secret/*`
and see hidden processes. Non-operator processes remain blocked. Whatever
marks a process as "operator" is up to you.

**8. Covert C2 channel: 8 pts**
Kernel and userland communicate with no obvious filesystem or network
artifact. `mykill` is provided as a reference; use it, modify it, or
replace it. Must support at minimum: status, toggle file hide, toggle
access block, toggle process hide, mark a PID as operator, trigger
injection.

**9. Kernel→userland shellcode injection: 8 pts**
On demo day the instructor hands you AArch64 PIC bytes. Inject them into
a sleeping process via your C2 channel. The target survives and the
shellcode produces its expected side effect.

**10. End-to-end demo: 10 pts**
Full COLDSPARK chain in a single sitting with no manual intervention
beyond launching the exploit script. Beachhead → LPE → reflective load
→ C2 → exfiltrate the three PIRs. No kernel panics.

**11. Cleanup: 5 pts**
`rmmod rootkit` succeeds. All hooks unregister, no cred/kretprobe leaks,
no oops, system usable after unload.

---

### Writeup / Poster (10 pts)

**12. `writeup/README.md`: 10 pts**
Submitted in your repo. Explain how each component works, your design
choices, what you'd do differently, and what would detect your rootkit.
Be honest about what doesn't work and why.

---

### Reproducibility (12 pts)

**13. `make test` passes: 12 pts**
Clean clone, `make`, `make test` must pass end-to-end on a fresh VM.
The instructor must be able to reproduce your demo without assistance.

---

**Base total: 100**

---

## Bonus (up to 50 pts)

**B1. Module self-hiding: +10 pts**
`lsmod` and `/proc/modules` do not list your module after load.
`rmmod rootkit` still works.

**B2. SNITCH evasion: +20 pts**
Complete the full attack chain with `snitch.ko` loaded and active,
without unloading or tampering with it, and without triggering any of
its 8 detectors. Partial credit for partial evasion.

**B3. LPE bonus path: +10 pts**
Implement a second LPE technique beyond your required one. `modprobe_path`
overwrite, `core_pattern` overwrite, ROP chain, anything that gets root
through a different mechanism than item 2.

**B4. Special feature: +10 to +20 pts**
Something we didn't ask for. Examples: persistence across reboots,
network-side covert channel, in-memory-only rootkit, process
masquerading, anti-forensics. 10 pts for a clean known technique,
20 pts for something genuinely interesting.

A sufficiently interesting special feature is an automatic A. Talk to
the instructor before demo day if you're aiming for this.

---

## Bonus accounting

Maximum possible: **150 points** (100 base + 50 bonus). Bonus exists to
give breathing room — recover points lost on one feature by going deep
on another.

---

## Deductions

A poor demo (panics, broken build, incomplete chain) will cost points on
the affected items. Demo day attendance is required: no-shows without a
prior excuse fail the course.

---

## Operator bypass (item 7)

Your rootkit hides things from non-operator processes. You need a way to
mark a process as "this is mine." When marked, it can open
`/tmp/secret/flag.txt`, see hidden PIDs in `/proc`, and see `secret/` in
`/tmp`.

The reference uses GID 1337 — `mykill add-gid <pid>` adds it, and hooks
check `cred->group_info`. You can use that or something else:
- A PID list maintained by your C2 channel
- A magic environment variable
- A magic file the operator opens to authenticate
- A specific parent process tree

Document your choice in `writeup/README.md`.

---

## Special feature ideas

**+10 (clean implementation of a known technique):**
- Hide network connections from `netstat`
- Persistence via `/etc/init.d`
- Process masquerading (`[kworker/0:0]`)
- Time-bomb activation
- Anti-debug: detect ptrace and disable C2

**+15–20 (creative or hard):**
- Network-side C2: DNS TXT records or ICMP timestamps
- In-memory only: never touch disk after deploy
- Anti-forensics: filter rootkit lines from dmesg
- Kernel→kernel injection: hijack another module's function pointer
- Operator resurrection: kernel respawns operator if it dies
- Crypto: PIRs encrypted on disk, C2 ships the key

**Auto-A bar:**
Something the instructor hasn't seen before in this class. Talk to the
instructor before demo day.
