# KSU Next LKM (.ko) build for sukisu_bridge
#
# This module is a standard Linux kernel module; it only uses the in-tree
# kretprobe/uaccess APIs plus our local uapi headers (include/uapi). It must be
# compiled against the *exact* kernel source tree that built this device's
# KernelSU Next kernel (GKI android12-5.10), because the KSU Next LKM loader
# maps it straight into that kernel.
#
# Set KDIR to that tree, e.g.:
#   make KDIR=/path/to/gki-android12-5.10-kernel
# or let it default to the running kernel's build dir (only works if you have
# that source tree installed).

obj-m := sukisu_bridge.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Our uapi reference headers (sukisu_uapi_supercall.h + app_profile.h) live in
# include/uapi; make them reachable from the compile.
ccflags-y := -I$(src)/include

# Diagnostic logging compile switch.
# By default the module is built in release mode: every pr_info() diagnostic
# (pid/comm/path/fd dumps) is compiled out so it cannot leak into the kernel
# ring buffer. Define SB_DEBUG to re-enable verbose diagnostics:
#   make ccflags-y+=-DSB_DEBUG
# ccflags-y += -DSB_DEBUG

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
