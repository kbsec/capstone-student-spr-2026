# Makefile for beachhead shellcode
#
# Assembles AArch64 PIC shellcode into a raw binary that can be
# sent to the MERIDIAN service via send_shellcode.py.
#
# Usage:
#   make                    — assemble all .S → .bin
#   make send               — send beachhead to target
#   make clean              — remove build artifacts
#
# Add your .S files to SOURCES as you write them.

include ../config.mk

AS      := $(CROSS_COMPILE)as
OBJCOPY := $(CROSS_COMPILE)objcopy

# List your shellcode source files here
SOURCES := $(wildcard *.S)
BINS    := $(SOURCES:.S=.bin)

all: $(BINS)

%.o: %.S
	$(AS) -o $@ $<

%.bin: %.o
	$(OBJCOPY) -O binary -j .text $< $@
	@wc -c < $@ | xargs -I{} echo "  $@ ({} bytes)"

send: beachhead.bin
	python3 ../tools/send_shellcode.py beachhead.bin

clean:
	rm -f *.o *.bin

.PHONY: all send clean
