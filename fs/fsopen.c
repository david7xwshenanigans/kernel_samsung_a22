/* Filesystem access-by-fd.
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/anon_inodes.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <uapi/linux/mount.h>
#include "internal.h"
#include "mount.h"

static inline const char *fetch_message_locked(struct fc_log *log, size_t len,
					       bool *need_free)
{
	const char *p;
	int index;

	if (unlikely(log->head == log->tail))
		return ERR_PTR(-ENODATA);

	index = log->tail & (ARRAY_SIZE(log->buffer) - 1);
	p = log->buffer[index];
	if (unlikely(strlen(p) > len))
		return ERR_PTR(-EMSGSIZE);

	log->buffer[index] = NULL;
	*need_free = log->need_free & (1 << index);
	log->need_free &= ~(1 << index);
	log->tail++;
	return p;
}

static ssize_t fscontext_read(struct file *file, char __user *_buf,
			      size_t len, loff_t *pos)
{
	struct fs_context *fc = file->private_data;
	const char *message;
	ssize_t ret;
	bool need_free;

	ret = mutex_lock_interruptible(&fc->uapi_mutex);
	if (ret < 0)
		return ret;

	message = fetch_message_locked(fc->log.log, len, &need_free);
	mutex_unlock(&fc->uapi_mutex);
	if (IS_ERR(message))
		return PTR_ERR(message);

	ret = strlen(message);
	if (copy_to_user(_buf, message, ret))
		ret = -EFAULT;
	if (need_free)
		kfree(message);
	return ret;
}

static int fscontext_release(struct inode *inode, struct file *file)
{
	struct fs_context *fc = file->private_data;

	if (fc) {
		file->private_data = NULL;
		put_fs_context(fc);
	}
	return 0;
}

const struct file_operations fscontext_fops = {
	.read		= fscontext_read,
	.release	= fscontext_release,
	.llseek		= no_llseek,
};

static int fscontext_create_fd(struct fs_context *fc, unsigned int o_flags)
{
	int fd;

	fd = anon_inode_getfd("[fscontext]", &fscontext_fops, fc,
			      O_RDWR | o_flags);
	if (fd < 0)
		put_fs_context(fc);
	return fd;
}

static int fscontext_alloc_log(struct fs_context *fc)
{
	fc->log.log = kzalloc(sizeof(*fc->log.log), GFP_KERNEL);
	if (!fc->log.log)
		return -ENOMEM;
	refcount_set(&fc->log.log->usage, 1);
	fc->log.log->owner = fc->fs_type->owner;
	return 0;
}

SYSCALL_DEFINE2(fsopen, const char __user *, _fs_name, unsigned int, flags)
{
	struct file_system_type *fs_type;
	struct fs_context *fc;
	const char *fs_name;
	int ret;

	if (!ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (flags & ~FSOPEN_CLOEXEC)
		return -EINVAL;

	fs_name = strndup_user(_fs_name, PAGE_SIZE);
	if (IS_ERR(fs_name))
		return PTR_ERR(fs_name);

	fs_type = get_fs_type(fs_name);
	kfree(fs_name);
	if (!fs_type)
		return -ENODEV;

	fc = fs_context_for_mount(fs_type, 0);
	put_filesystem(fs_type);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	fc->phase = FS_CONTEXT_CREATE_PARAMS;
	ret = fscontext_alloc_log(fc);
	if (ret < 0) {
		put_fs_context(fc);
		return ret;
	}

	return fscontext_create_fd(fc, flags & FSOPEN_CLOEXEC ? O_CLOEXEC : 0);
}

SYSCALL_DEFINE3(fspick, int, dfd, const char __user *, path,
		unsigned int, flags)
{
	struct fs_context *fc;
	struct path target;
	unsigned int lookup_flags;
	int ret;

	if (!ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (flags & ~(FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW |
		      FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH))
		return -EINVAL;

	lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	if (flags & FSPICK_SYMLINK_NOFOLLOW)
		lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & FSPICK_NO_AUTOMOUNT)
		lookup_flags &= ~LOOKUP_AUTOMOUNT;
	if (flags & FSPICK_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	ret = user_path_at(dfd, path, lookup_flags, &target);
	if (ret < 0)
		return ret;

	ret = -EINVAL;
	if (target.mnt->mnt_root != target.dentry)
		goto out_path;

	fc = fs_context_for_reconfigure(target.dentry, 0, 0);
	if (IS_ERR(fc)) {
		ret = PTR_ERR(fc);
		goto out_path;
	}

	fc->root_mnt = mntget(target.mnt);
	fc->phase = FS_CONTEXT_RECONF_PARAMS;
	ret = fscontext_alloc_log(fc);
	if (ret < 0) {
		put_fs_context(fc);
		goto out_path;
	}

	path_put(&target);
	return fscontext_create_fd(fc, flags & FSPICK_CLOEXEC ? O_CLOEXEC : 0);

out_path:
	path_put(&target);
	return ret;
}

static int vfs_fsconfig_locked(struct fs_context *fc, int cmd,
			       struct fs_parameter *param)
{
	struct super_block *sb;
	int ret;

	ret = finish_clean_context(fc);
	if (ret)
		return ret;

	switch (cmd) {
	case FSCONFIG_CMD_CREATE:
		if (fc->phase != FS_CONTEXT_CREATE_PARAMS)
			return -EBUSY;
		if (!mount_capable(fc))
			return -EPERM;
		fc->phase = FS_CONTEXT_CREATING;
		ret = vfs_get_tree(fc);
		if (ret)
			break;
		sb = fc->root->d_sb;
		up_write(&sb->s_umount);
		fc->phase = FS_CONTEXT_AWAITING_MOUNT;
		return 0;

	case FSCONFIG_CMD_RECONFIGURE:
		if (fc->phase != FS_CONTEXT_RECONF_PARAMS)
			return -EBUSY;
		fc->phase = FS_CONTEXT_RECONFIGURING;
		sb = fc->root->d_sb;
		down_write(&sb->s_umount);
		ret = reconfigure_super(fc);
		up_write(&sb->s_umount);
		if (ret)
			break;
		vfs_clean_context(fc);
		return 0;

	default:
		if (fc->phase != FS_CONTEXT_CREATE_PARAMS &&
		    fc->phase != FS_CONTEXT_RECONF_PARAMS)
			return -EBUSY;
		return vfs_parse_fs_param(fc, param);
	}

	fc->phase = FS_CONTEXT_FAILED;
	return ret;
}

SYSCALL_DEFINE5(fsconfig,
		int, fd,
		unsigned int, cmd,
		const char __user *, _key,
		const void __user *, _value,
		int, aux)
{
	struct fs_context *fc;
	struct fd f;
	struct fd value_fd;
	struct fs_parameter param = {
		.type = fs_value_is_undefined,
	};
	int ret;

	if (fd < 0)
		return -EINVAL;

	switch (cmd) {
	case FSCONFIG_SET_FLAG:
	case FSCONFIG_CMD_CREATE:
	case FSCONFIG_CMD_RECONFIGURE:
		break;
	case FSCONFIG_SET_STRING:
	case FSCONFIG_SET_BINARY:
	case FSCONFIG_SET_PATH:
	case FSCONFIG_SET_PATH_EMPTY:
	case FSCONFIG_SET_FD:
		if (!_key)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	if (_key) {
		param.key = strndup_user(_key, 256);
		if (IS_ERR(param.key))
			return PTR_ERR(param.key);
	}

	switch (cmd) {
	case FSCONFIG_SET_FLAG:
		param.type = fs_value_is_flag;
		break;
	case FSCONFIG_SET_STRING:
		param.string = strndup_user(_value, PAGE_SIZE);
		if (IS_ERR(param.string)) {
			ret = PTR_ERR(param.string);
			goto out_key;
		}
		param.type = fs_value_is_string;
		param.size = strlen(param.string);
		break;
	case FSCONFIG_SET_BINARY:
		if (aux <= 0 || aux > PAGE_SIZE) {
			ret = -EINVAL;
			goto out_key;
		}
		param.blob = memdup_user(_value, aux);
		if (IS_ERR(param.blob)) {
			ret = PTR_ERR(param.blob);
			goto out_key;
		}
		param.type = fs_value_is_blob;
		param.size = aux;
		break;
	case FSCONFIG_SET_PATH:
	case FSCONFIG_SET_PATH_EMPTY:
		param.name = getname(_value);
		if (IS_ERR(param.name)) {
			ret = PTR_ERR(param.name);
			goto out_key;
		}
		param.type = cmd == FSCONFIG_SET_PATH ?
			fs_value_is_filename : fs_value_is_filename_empty;
		param.dirfd = aux;
		break;
	case FSCONFIG_SET_FD:
		value_fd = fdget(aux);
		if (!value_fd.file) {
			ret = -EBADF;
			goto out_key;
		}
		param.file = value_fd.file;
		param.type = fs_value_is_file;
		param.dirfd = aux;
		break;
	}

	f = fdget(fd);
	if (!f.file) {
		ret = -EBADF;
		goto out_param;
	}
	if (f.file->f_op != &fscontext_fops) {
		ret = -EINVAL;
		goto out_fd;
	}

	fc = f.file->private_data;
	ret = mutex_lock_interruptible(&fc->uapi_mutex);
	if (ret < 0)
		goto out_fd;

	ret = vfs_fsconfig_locked(fc, cmd, &param);
	mutex_unlock(&fc->uapi_mutex);

out_fd:
	fdput(f);
out_param:
	if (cmd == FSCONFIG_SET_FD)
		fdput(value_fd);
	if (param.type == fs_value_is_filename ||
	    param.type == fs_value_is_filename_empty)
		putname(param.name);
	kfree(param.blob);
out_key:
	kfree(param.key);
	return ret;
}
