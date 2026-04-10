# Makefile for MERIDIAN DEFENSE GROUP service
#
# Cross-compiles the vulnerable TCP server for AArch64.
#
# Usage:
#   make          — build meridian (aarch64)
#   make clean    — remove build artifacts

include ../config.mk

CC      := $(CC_CROSS)
CFLAGS  := -Wall -Wextra -O2 -static

all: meridian

meridian: meridian.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f meridian

.PHONY: all clean
