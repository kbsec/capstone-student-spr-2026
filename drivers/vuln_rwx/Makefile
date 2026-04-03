# Makefile for vuln_rwx — vulnerable JIT engine driver
#
# Challenge 7: RWX Kernel Shellcode
#
# Usage:
#   make          — build vuln_rwx.ko
#   make clean    — remove build artifacts
#   make load     — insmod vuln_rwx.ko
#   make unload   — rmmod vuln_rwx

# kbuild variables (visible during kernel build pass)
obj-m := vuln_rwx.o

# User-facing targets (only when invoked directly, not by kbuild)
ifeq ($(KERNELRELEASE),)

include ../../config.mk

PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean

# ── Convenience targets (require root) ────────────────────────────────────────

load:
	sudo insmod vuln_rwx.ko
	sudo chmod 666 /dev/vuln_rwx

unload:
	sudo rmmod vuln_rwx

.PHONY: all clean load unload

endif
