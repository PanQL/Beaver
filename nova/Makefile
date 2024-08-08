#
# Makefile for the linux NOVA filesystem routines.
#

# obj-$(CONFIG_NOVA_FS) += nova.o
obj-m += nova.o

nova-y := balloc.o bbuild.o checksum.o dax.o dir.o file.o gc.o inode.o ioctl.o \
	journal.o log.o mprotect.o namei.o parity.o rebuild.o snapshot.o stats.o \
	super.o symlink.o perf.o
