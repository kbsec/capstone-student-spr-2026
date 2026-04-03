# config.mk — Cross-compile settings for capstone project
#
# Self-contained: no LAB_ROOT dependency.
# Override any variable on the command line:
#   make KDIR=/path/to/linux-6.6

# Project root — resolved from the location of this file, not $(CURDIR).
# This ensures KDIR/SHARED are correct even when included from subdirectories.
PROJECT_ROOT  ?= $(dir $(lastword $(MAKEFILE_LIST)))

ARCH          ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-
CC_CROSS      ?= aarch64-linux-gnu-gcc

# Kernel headers for out-of-tree module builds
KDIR          ?= $(abspath $(PROJECT_ROOT)/kernel/linux-6.6)

# Shared folder for QEMU 9P mount
SHARED        ?= $(abspath $(PROJECT_ROOT)/shared)
