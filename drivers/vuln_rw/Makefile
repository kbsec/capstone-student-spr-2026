# Makefile for vuln_rw — vulnerable debug interface driver
#
# Challenges 8 & 9: Arbitrary kernel read/write
#
# Usage:
#   make          — build vuln_rw.ko
#   make clean    — remove build artifacts
#   make load     — insmod vuln_rw.ko
#   make unload   — rmmod vuln_rw

# kbuild variables (visible during kernel build pass)
obj-m := vuln_rw.o

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
	sudo insmod vuln_rw.ko
	sudo chmod 666 /dev/vuln_rw

unload:
	sudo rmmod vuln_rw

.PHONY: all clean load unload

endif
