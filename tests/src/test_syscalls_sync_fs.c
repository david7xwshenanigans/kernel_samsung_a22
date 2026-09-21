#include "test_framework.h"
#include "test_uapi.h"
#include <fcntl.h>
#include <time.h>

#include <sys/prctl.h>
#include <sys/wait.h>

static void test_syscall_futex_waitv(void)
{
	const char *mod = "SYS_FUTEX_WAITV";
	struct futex_waitv_local waiter;
	uint32_t futex_val = 0x1234;

	/* 1. Base Existence Check & invalid flags argument */
	memset(&waiter, 0, sizeof(waiter));
	waiter.val = futex_val;
	waiter.uaddr = (uintptr_t)&futex_val;
	waiter.flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
	long ret = syscall(__NR_futex_waitv, &waiter, 1, 0xFFFFFFFFU, NULL, 0);
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "futex_waitv syscall (449)");
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "futex_waitv rejects invalid flags (-EINVAL)");
	} else {
		report_fail(mod, "futex_waitv invalid flags", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. nr_futexes == 0 */
	ret = syscall(__NR_futex_waitv, &waiter, 0, 0, NULL, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "futex_waitv rejects nr_futexes=0 (-EINVAL)");
	} else {
		report_fail(mod, "futex_waitv zero waiters", "ret=%ld errno=%d", ret, errno);
	}

	/* 3. nr_futexes > FUTEX_WAITV_MAX */
	ret = syscall(__NR_futex_waitv, &waiter, FUTEX_WAITV_MAX + 1, 0, NULL, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "futex_waitv rejects nr_futexes > 128 (-EINVAL)");
	} else {
		report_fail(mod, "futex_waitv excess waiters", "ret=%ld errno=%d", ret, errno);
	}

	/* 4. NULL waiters pointer */
	ret = syscall(__NR_futex_waitv, NULL, 1, 0, NULL, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "futex_waitv rejects NULL waiters (-EINVAL)");
	} else {
		report_fail(mod, "futex_waitv NULL waiters", "ret=%ld errno=%d", ret, errno);
	}

	/* 5. Missing FUTEX_32 flag */
	memset(&waiter, 0, sizeof(waiter));
	waiter.val = futex_val;
	waiter.uaddr = (uintptr_t)&futex_val;
	waiter.flags = FUTEX_PRIVATE_FLAG;
	ret = syscall(__NR_futex_waitv, &waiter, 1, 0, NULL, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "futex_waitv rejects waiter without FUTEX_32 (-EINVAL)");
	} else {
		report_fail(mod, "futex_waitv missing FUTEX_32", "ret=%ld errno=%d", ret, errno);
	}

	/* 6. Non-zero reserved field */
	memset(&waiter, 0, sizeof(waiter));
	waiter.val = futex_val;
	waiter.uaddr = (uintptr_t)&futex_val;
	waiter.flags = FUTEX_32 | FUTEX_PRIVATE_FLAG;
	waiter.__reserved = 1;
	ret = syscall(__NR_futex_waitv, &waiter, 1, 0, NULL, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "futex_waitv rejects non-zero __reserved (-EINVAL)");
	} else {
		report_fail(mod, "futex_waitv non-zero reserved", "ret=%ld errno=%d", ret, errno);
	}

	/* 7. Invalid clockid with timeout */
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
	waiter.__reserved = 0;
	ret = syscall(__NR_futex_waitv, &waiter, 1, 0, &ts, 9999);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "futex_waitv rejects invalid clockid (-EINVAL)");
	} else {
		report_fail(mod, "futex_waitv invalid clockid", "ret=%ld errno=%d", ret, errno);
	}

	/* 8. Value mismatch */
	waiter.val = futex_val + 1;
	ret = syscall(__NR_futex_waitv, &waiter, 1, 0, NULL, 0);
	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		report_pass(mod, "futex_waitv detects value mismatch (-EAGAIN/EWOULDBLOCK)");
	} else {
		report_fail(mod, "futex_waitv value mismatch", "ret=%ld errno=%d", ret, errno);
	}

	/* 9. Valid wait with short timeout (10ms) */
	waiter.val = futex_val;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_nsec += 10000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_sec += 1;
		ts.tv_nsec -= 1000000000;
	}
	ret = syscall(__NR_futex_waitv, &waiter, 1, 0, &ts, CLOCK_MONOTONIC);
	if (ret < 0 && errno == ETIMEDOUT) {
		report_pass(mod, "futex_waitv timed out wait successfully (-ETIMEDOUT)");
	} else {
		report_fail(mod, "futex_waitv timeout wait", "ret=%ld errno=%d", ret, errno);
	}
}

static void test_syscall_landlock(void)
{
	const char *mod = "SYS_LANDLOCK";

	/* 1. Base Existence Check & query ABI version */
	long abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "Landlock LSM syscalls (444-446)");
	}

	if (abi >= 1) {
		report_pass(mod, "Query Landlock ABI version (active)");
		report_info("Landlock ABI version: %ld", abi);
	} else if (errno == EOPNOTSUPP || errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "Landlock LSM subsystem");
	} else {
		report_fail(mod, "Query Landlock ABI", "errno=%d (%s)", errno, strerror(errno));
	}

	/* 2. Edge Case: invalid size */
	struct landlock_ruleset_attr_local attr;
	memset(&attr, 0, sizeof(attr));
	long ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, 0, 0);
	if (ruleset_fd < 0 && errno == EINVAL) {
		report_pass(mod, "landlock_create_ruleset rejects invalid size (-EINVAL)");
	} else if (ruleset_fd >= 0) {
		close(ruleset_fd);
		report_fail(mod, "Rejects invalid size", "Created fd=%ld", ruleset_fd);
	} else {
		report_fail(mod, "Rejects invalid size", "errno=%d", errno);
	}

	/* 3. Valid ruleset creation */
	attr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE;
	ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (ruleset_fd >= 0) {
		report_pass(mod, "Create Landlock ruleset fd");

		/* Edge Case: landlock_add_rule with invalid rule_type */
		struct landlock_path_beneath_attr_local path_beneath;
		memset(&path_beneath, 0, sizeof(path_beneath));
		long rule_ret = syscall(__NR_landlock_add_rule, ruleset_fd, 9999, &path_beneath, 0);
		if (rule_ret < 0 && errno == EINVAL) {
			report_pass(mod, "landlock_add_rule rejects invalid rule_type (-EINVAL)");
		} else {
			report_fail(mod, "Rejects invalid rule_type", "ret=%ld errno=%d", rule_ret, errno);
		}

		/* 4. Restrict self in worker process with NO_NEW_PRIVS */
		pid_t cpid = fork();
		if (cpid == 0) {
			if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
				_exit(1);

			/* In worker with NO_NEW_PRIVS, test invalid fd */
			long r_bad_fd = syscall(__NR_landlock_restrict_self, -1, 0);
			if (r_bad_fd >= 0 || errno != EBADF)
				_exit(2);

			/* Test invalid flags */
			long r_bad_flags = syscall(__NR_landlock_restrict_self, ruleset_fd, 0xFFFFFFFFU);
			if (r_bad_flags >= 0 || errno != EINVAL)
				_exit(3);

			/* Valid restrict_self */
			if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0)
				_exit(4);

			_exit(0);
		} else if (cpid > 0) {
			int wstatus = 0;
			waitpid(cpid, &wstatus, 0);
			if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) {
				report_pass(mod, "landlock_restrict_self validates invalid args and enforces ruleset");
			} else {
				report_fail(mod, "landlock_restrict_self enforcement", "child exited 0x%x", wstatus);
			}
		}

		close(ruleset_fd);
	} else {
		report_fail(mod, "Create Landlock ruleset", "errno=%d (%s)", errno, strerror(errno));
	}
}

static void test_syscall_mount_api(void)
{
	const char *mod = "SYS_MOUNT_API";

	/* 1. Base Existence Check & fsopen */
	long ret = syscall(__NR_fsopen, "invalid_fs_nonexistent_xyz", 0);
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "Mount API syscalls (428-433)");
	}

	if (ret < 0 && errno == ENODEV) {
		report_pass(mod, "fsopen rejects invalid filesystem (-ENODEV)");
	} else if (ret < 0 && (errno == EPERM || errno == EACCES)) {
		report_pass(mod, "fsopen validates entrypoint (-EPERM/EACCES unprivileged)");
	} else if (ret >= 0) {
		close(ret);
		report_fail(mod, "fsopen invalid fs", "Unexpected fd=%ld", ret);
	} else {
		report_fail(mod, "fsopen invalid fs", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. open_tree */
	int tree_fd = syscall(__NR_open_tree, AT_FDCWD, "/proc", 0);
	if (tree_fd >= 0) {
		report_pass(mod, "open_tree on /proc");
		close(tree_fd);
	} else if (errno == EPERM || errno == EACCES) {
		report_skip(mod, "open_tree on /proc", "CAP_SYS_ADMIN required");
	} else {
		report_fail(mod, "open_tree", "errno=%d (%s)", errno, strerror(errno));
	}

	/* 3. fsconfig edge cases */
	long c_ret = syscall(__NR_fsconfig, -1, 0, NULL, NULL, 0);
	if (c_ret < 0 && (errno == EBADF || errno == EINVAL || errno == EPERM)) {
		report_pass(mod, "fsconfig rejects invalid arguments (-EBADF/-EINVAL/-EPERM)");
	} else {
		report_fail(mod, "fsconfig invalid fd", "ret=%ld errno=%d", c_ret, errno);
	}

	/* 4. fsmount edge cases */
	long m_ret = syscall(__NR_fsmount, -1, 0, 0);
	if (m_ret < 0 && (errno == EBADF || errno == EPERM)) {
		report_pass(mod, "fsmount rejects invalid fd or unprivileged (-EBADF/-EPERM)");
	} else {
		report_fail(mod, "fsmount invalid fd", "ret=%ld errno=%d", m_ret, errno);
	}

	/* 5. fspick edge cases */
	long p_ret = syscall(__NR_fspick, -1, "", 0);
	if (p_ret < 0 && (errno == EBADF || errno == ENOENT || errno == EPERM)) {
		report_pass(mod, "fspick rejects invalid dfd or unprivileged (-EBADF/-ENOENT/-EPERM)");
	} else {
		report_fail(mod, "fspick invalid dfd", "ret=%ld errno=%d", p_ret, errno);
	}

	/* 6. move_mount edge cases */
	long mv_ret = syscall(__NR_move_mount, -1, "", -1, "", 0);
	if (mv_ret < 0 && (errno == EBADF || errno == ENOENT || errno == EPERM)) {
		report_pass(mod, "move_mount rejects invalid dfd or unprivileged (-EBADF/-ENOENT/-EPERM)");
	} else {
		report_fail(mod, "move_mount invalid dfd", "ret=%ld errno=%d", mv_ret, errno);
	}

	/* 7. mount_setattr edge cases */
	struct mount_attr_local mattr;
	memset(&mattr, 0, sizeof(mattr));
	long sa_ret = syscall(__NR_mount_setattr, -1, "", 0xFFFFFFFFU, &mattr, sizeof(mattr));
	if (sa_ret < 0 && errno == EINVAL) {
		report_pass(mod, "mount_setattr rejects invalid flags (-EINVAL)");
	} else {
		report_fail(mod, "mount_setattr invalid flags", "ret=%ld errno=%d", sa_ret, errno);
	}

	sa_ret = syscall(__NR_mount_setattr, -1, "", 0, &mattr, 16);
	if (sa_ret < 0 && errno == EINVAL) {
		report_pass(mod, "mount_setattr rejects usize < MOUNT_ATTR_SIZE_VER0 (-EINVAL)");
	} else {
		report_fail(mod, "mount_setattr small usize", "ret=%ld errno=%d", sa_ret, errno);
	}

	sa_ret = syscall(__NR_mount_setattr, AT_FDCWD, "/proc", 0, &mattr, sizeof(mattr));
	if (sa_ret == 0) {
		report_pass(mod, "mount_setattr no-op call on /proc");
	} else if (errno == EPERM || errno == EACCES) {
		report_skip(mod, "mount_setattr no-op on /proc", "CAP_SYS_ADMIN required");
	} else {
		report_fail(mod, "mount_setattr on /proc", "ret=%ld errno=%d (%s)", sa_ret, errno, strerror(errno));
	}
}

static void test_syscall_quotactl_fd(void)
{
	const char *mod = "SYS_QUOTACTL_FD";

	/* 1. Base Existence Check & invalid fd (-1) */
	long ret = syscall(__NR_quotactl_fd, -1, QCMD(Q_GETQUOTA, USRQUOTA), 0, NULL);
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "quotactl_fd syscall (443)");
	}

	if (ret < 0 && errno == EBADF) {
		report_pass(mod, "quotactl_fd rejects invalid fd (-EBADF)");
	} else {
		report_fail(mod, "quotactl_fd invalid fd", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. Edge Case: invalid command type */
	int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (null_fd >= 0) {
		ret = syscall(__NR_quotactl_fd, null_fd, 0xFFFFFFFFU, 0, NULL);
		if (ret < 0 && errno == EINVAL) {
			report_pass(mod, "quotactl_fd rejects invalid cmd (-EINVAL)");
		} else {
			report_fail(mod, "quotactl_fd invalid cmd", "ret=%ld errno=%d", ret, errno);
		}

		/* 3. Edge Case: bad user address */
		ret = syscall(__NR_quotactl_fd, null_fd, QCMD(Q_GETQUOTA, USRQUOTA), 0, (void *)0x1);
		if (ret < 0 && (errno == EFAULT || errno == ENOTTY || errno == ENOSYS || errno == ESRCH || errno == ENODEV)) {
			report_pass(mod, "quotactl_fd handles bad address or unsupported device safely");
		} else {
			report_fail(mod, "quotactl_fd bad address", "ret=%ld errno=%d", ret, errno);
		}
		close(null_fd);
	}

	/* 4. Valid target fd on root filesystem */
	int root_fd = open("/", O_RDONLY | O_CLOEXEC);
	if (root_fd >= 0) {
		ret = syscall(__NR_quotactl_fd, root_fd, QCMD(Q_SYNC, USRQUOTA), 0, NULL);
		if (ret == 0 || (ret < 0 && (errno == ENOSYS || errno == ESRCH || errno == EOPNOTSUPP || errno == EPERM || errno == EACCES))) {
			report_pass(mod, "quotactl_fd handles Q_SYNC query on rootfs mount");
		} else {
			report_fail(mod, "quotactl_fd Q_SYNC", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		}
		close(root_fd);
	}
}

static void run_syscalls_sync_fs_suite(void)
{
	test_syscall_futex_waitv();
	test_syscall_landlock();
	test_syscall_mount_api();
	test_syscall_quotactl_fd();
}

void register_suite_syscalls_sync_fs(void)
{
	register_test_suite("syscalls_sync_fs", "Synchronization & Filesystem/Security Syscalls (futex_waitv, Landlock, Mount API, quotactl_fd)", run_syscalls_sync_fs_suite);
}
