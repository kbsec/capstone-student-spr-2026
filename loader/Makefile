# Makefile for reflective loader
#
# Students implement a reflective kernel module loader here.
#
# Usage:
#   make          — build loader
#   make clean    — remove build artifacts

include ../config.mk

CC     := $(CC_CROSS)
CFLAGS := -Wall -Wextra -static

# Uncomment when you have source files:
# TARGETS := loader

TARGETS :=

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
