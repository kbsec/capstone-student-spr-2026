# Makefile for LKM rootkit
#
# Builds rootkit.ko — a multi-file kernel module that hides files,
# hides processes, blocks access, conceals itself, handles C2, and
# injects shellcode.
#
# Usage:
#   make          — build rootkit.ko
#   make clean    — remove build artifacts
#   make load     — insmod rootkit.ko
#   make unload   — rmmod rootkit

# kbuild variables (visible during kernel build pass)
obj-m := rootkit.o

# Multi-file module: rootkit.ko is linked from these object files
rootkit-objs := src/rootkit.o \
                src/file_hide.o \
                src/proc_hide.o \
                src/c2.o \
                src/inject.o

# Tell the compiler where to find our headers
ccflags-y := -I$(src)/src

# User-facing targets (only when invoked directly, not by kbuild)
ifeq ($(KERNELRELEASE),)

include ../config.mk

PWD := $(shell pwd)

# Default target: build the module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean

# ── Convenience targets (require root) ────────────────────────────────────────

load:
	sudo insmod rootkit.ko

unload:
	sudo rmmod rootkit

reload: unload load

log:
	sudo dmesg | tail -40

log-rootkit:
	sudo dmesg | grep rootkit

info:
	modinfo rootkit.ko 2>/dev/null || echo "Module not built yet — run 'make' first"

status:
	@lsmod | grep rootkit || echo "rootkit is not loaded"
	@ls /sys/module/rootkit/ 2>/dev/null && echo "(but /sys/module/rootkit/ exists)" || true

.PHONY: all clean load unload reload log log-rootkit info status

endif
