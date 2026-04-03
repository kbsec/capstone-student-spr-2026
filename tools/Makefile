# Makefile for capstone rootkit tools
#
# Builds mykill (extended C2) and rkcmd (simple C2 wrapper)
#
# Usage:
#   make          — build all tools
#   make clean    — remove build artifacts

include ../config.mk

CC     := $(CC_CROSS)
CFLAGS := -Wall -Wextra -static

all: mykill rkcmd

mykill: mykill.c
	$(CC) $(CFLAGS) -o $@ $<

rkcmd: rkcmd.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f mykill rkcmd

.PHONY: all clean
