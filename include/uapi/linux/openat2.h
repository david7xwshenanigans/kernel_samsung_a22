/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_OPENAT2_H
#define _UAPI_LINUX_OPENAT2_H

#include <linux/types.h>

struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

#define RESOLVE_NO_XDEV		0x01
#define RESOLVE_NO_MAGICLINKS	0x02
#define RESOLVE_NO_SYMLINKS	0x04
#define RESOLVE_BENEATH		0x08
#define RESOLVE_IN_ROOT		0x10
#define RESOLVE_CACHED		0x20

#endif /* _UAPI_LINUX_OPENAT2_H */
