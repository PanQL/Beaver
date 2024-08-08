# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the shadow filesystem.
#

obj-$(CONFIG_SHADOW_FS) += shadow.o
# obj-m += shadow.o

shadow-y := super.o inode1.o write.o palloc.o \
						util.o dir.o namei1.o log.o stats.o \
						copy.o syncup.o cp.o

ccflags-y := -O3
# ccflags-y += -fno-inline -Wuninitialized
# CFLAGS_write.o += -DDEBUG
CFLAGS_copy.o += -mavx512f
