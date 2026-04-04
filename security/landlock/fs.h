/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Filesystem management and hooks
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#ifndef _SECURITY_LANDLOCK_FS_H
#define _SECURITY_LANDLOCK_FS_H

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/wait.h>

#include "ruleset.h"
#include "setup.h"

/**
 * struct landlock_inode_security - Inode security blob
 *
 * Enable to reference a &struct landlock_object tied to an inode (i.e.
 * underlying object).
 */
struct landlock_inode_security {
	/**
	 * @object: Weak pointer to an allocated object.  All assignments of a
	 * new object are protected by the underlying inode->i_lock.  However,
	 * atomically disassociating @object from the inode is only protected
	 * by @object->lock, from the time @object's usage refcount drops to
	 * zero to the time this pointer is nulled out (cf. release_inode() and
	 * hook_sb_delete()).  Indeed, such disassociation doesn't require
	 * inode->i_lock thanks to the careful rcu_access_pointer() check
	 * performed by get_inode_object().
	 */
	struct landlock_object __rcu *object;
};

/**
 * struct landlock_superblock_security - Per-superblock Landlock state
 *
 * Enable hook_sb_delete() to wait for concurrent calls to release_inode().
 */
struct landlock_superblock_security {
	struct list_head node;
	struct super_block *sb;
	/**
	 * @inode_refs: Number of pending inodes (from this superblock) that
	 * are being released by release_inode().
	 */
	atomic_long_t inode_refs;
	wait_queue_head_t inode_wait;
};

static inline struct landlock_inode_security *landlock_inode(
		const struct inode *const inode)
{
	return inode->i_security + landlock_blob_sizes.lbs_inode;
}

struct landlock_superblock_security *
landlock_superblock(const struct super_block *const superblock);

__init void landlock_add_fs_hooks(void);

int landlock_append_fs_rule(struct landlock_ruleset *const ruleset,
		const struct path *const path, u32 access_hierarchy);

#endif /* _SECURITY_LANDLOCK_FS_H */
