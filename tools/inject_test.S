/*
 * inject_test.S — AArch64 PIC shellcode for testing injection
 *
 * Creates /tmp/pwned containing "INJECTED-1337 pid=<pid> ppid=<ppid>\n"
 * then returns to the original PC via br x28.
 *
 * This is provided pre-assembled as inject_test.bin for students to verify
 * their injection machinery works before writing their own shellcode.
 *
 * Register convention:
 *   x28 = saved PC (set by the kernel injection code)
 *   x19 = getpid() result (callee-saved)
 *   x20 = getppid() result (callee-saved)
 *   x21 = fd from openat (callee-saved)
 *
 * AArch64 syscall numbers:
 *   openat  = 56
 *   write   = 64
 *   close   = 57
 *   getpid  = 172
 *   getppid = 173
 *
 * Build:
 *   aarch64-linux-gnu-as -o inject_test.o inject_test.S
 *   aarch64-linux-gnu-objcopy -O binary -j .text inject_test.o inject_test.bin
 */

.text
.global _start
_start:
	/* ── Save callee-saved registers ──────────────────────── */
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!

	/* ── getpid() → x19 ──────────────────────────────────── */
	mov	x8, #172		/* __NR_getpid */
	svc	#0
	mov	x19, x0

	/* ── getppid() → x20 ─────────────────────────────────── */
	mov	x8, #173		/* __NR_getppid */
	svc	#0
	mov	x20, x0

	/* ── openat(AT_FDCWD, "/tmp/pwned", O_WRONLY|O_CREAT|O_TRUNC, 0644) ─ */
	mov	x0, #-100		/* AT_FDCWD */
	adr	x1, path_str		/* "/tmp/pwned" */
	mov	x2, #(0x41 | 0x200)	/* O_WRONLY | O_CREAT | O_TRUNC */
	movk	x2, #0, lsl #16
	mov	x3, #0x1a4		/* 0644 octal = 420 decimal */
	mov	x8, #56			/* __NR_openat */
	svc	#0
	mov	x21, x0			/* fd → x21 */

	/* Check for error */
	cmp	x21, #0
	b.lt	.Lrestore

	/* ── Build message on stack ──────────────────────────── */
	/* Write static prefix "INJECTED-1337 pid=" */
	adr	x1, msg_prefix
	mov	x2, #19			/* len("INJECTED-1337 pid=") */
	mov	x0, x21
	mov	x8, #64			/* __NR_write */
	svc	#0

	/* ── Write PID as decimal ────────────────────────────── */
	sub	sp, sp, #32		/* temp buffer on stack */
	mov	x0, x19			/* pid value */
	add	x1, sp, #31		/* end of buffer */
	mov	x2, #0
	strb	w2, [x1]		/* null terminator */

.Lpid_loop:
	mov	x3, #10
	udiv	x4, x0, x3		/* x4 = x0 / 10 */
	msub	x5, x4, x3, x0		/* x5 = x0 % 10 */
	add	x5, x5, #'0'		/* ASCII digit */
	sub	x1, x1, #1
	strb	w5, [x1]
	add	x2, x2, #1		/* count digits */
	mov	x0, x4
	cbnz	x0, .Lpid_loop

	/* write(fd, digit_str, digit_count) */
	mov	x0, x21
	mov	x8, #64
	svc	#0

	/* ── Write " ppid=" ──────────────────────────────────── */
	adr	x1, msg_ppid
	mov	x2, #6			/* len(" ppid=") */
	mov	x0, x21
	mov	x8, #64
	svc	#0

	/* ── Write PPID as decimal ───────────────────────────── */
	add	x1, sp, #31
	mov	x2, #0
	strb	w2, [x1]
	mov	x0, x20			/* ppid value */

.Lppid_loop:
	mov	x3, #10
	udiv	x4, x0, x3
	msub	x5, x4, x3, x0
	add	x5, x5, #'0'
	sub	x1, x1, #1
	add	x2, x2, #1
	strb	w5, [x1]
	mov	x0, x4
	cbnz	x0, .Lppid_loop

	mov	x0, x21
	mov	x8, #64
	svc	#0

	/* ── Write newline ───────────────────────────────────── */
	adr	x1, msg_nl
	mov	x2, #1
	mov	x0, x21
	mov	x8, #64
	svc	#0

	add	sp, sp, #32		/* free temp buffer */

	/* ── close(fd) ───────────────────────────────────────── */
	mov	x0, x21
	mov	x8, #57			/* __NR_close */
	svc	#0

.Lrestore:
	/* ── Restore registers ───────────────────────────────── */
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16

	/* ── Return -EINTR so interrupted syscall restarts ───── */
	mov	x0, #-4		/* -EINTR */

	/* ── Return to original PC ───────────────────────────── */
	br	x28

/* ── String constants (PIC — accessed via adr) ───────────────────────────── */

path_str:
	.asciz	"/tmp/pwned"

msg_prefix:
	.ascii	"INJECTED-1337 pid="

msg_ppid:
	.ascii	" ppid="

msg_nl:
	.ascii	"\n"

	.align	2	/* pad to 4-byte boundary */
