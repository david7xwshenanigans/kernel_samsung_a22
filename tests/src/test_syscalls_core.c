#include "test_framework.h"
#include "test_uapi.h"
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <signal.h>

static void test_syscall_clone3(void)
{
	const char *mod = "SYS_CLONE3";
	struct clone_args_local cl_args;

	/* 1. Base Existence Check & undersized struct rejection */
	memset(&cl_args, 0, sizeof(cl_args));
	long ret = syscall(__NR_clone3, &cl_args, 32); /* Size < 64 bytes is invalid on all kernels */
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "clone3 syscall (435)");
	}

	if (ret == 0) {
		_exit(0); /* Safety in case a kernel forked unexpectedly */
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects undersized struct clone_args (-EINVAL)");
	} else {
		report_fail(mod, "Rejects undersized clone_args", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		if (ret > 0) waitpid(ret, NULL, 0);
	}

	/* 2. Edge Case: unknown clone3 flags */
	memset(&cl_args, 0, sizeof(cl_args));
	cl_args.flags = 0x8000000000000000ULL; /* Unknown high bit flag */
	cl_args.exit_signal = SIGCHLD;
	ret = syscall(__NR_clone3, &cl_args, sizeof(cl_args));
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects unknown clone3 flags (-EINVAL)");
	} else {
		report_fail(mod, "Rejects unknown flags", "ret=%ld errno=%d", ret, errno);
		if (ret > 0) waitpid(ret, NULL, 0);
	}

	/* 3. Happy Path: fork a child process via clone3 */
	memset(&cl_args, 0, sizeof(cl_args));
	cl_args.exit_signal = SIGCHLD;
	pid_t pid = syscall(__NR_clone3, &cl_args, sizeof(cl_args));
	if (pid == 0) {
		_exit(42);
	} else if (pid > 0) {
		int wstatus;
		waitpid(pid, &wstatus, 0);
		if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 42)
			report_pass(mod, "Fork child via clone3 and reap exit status 42");
		else
			report_fail(mod, "Fork via clone3", "Child exited with bad status 0x%x", wstatus);
	} else {
		report_fail(mod, "Fork via clone3", "ret=%ld errno=%d (%s)", (long)pid, errno, strerror(errno));
	}
}

static void test_syscall_openat2(void)
{
	const char *mod = "SYS_OPENAT2";
	struct open_how_local how;

	/* 1. Base Existence Check & undersized struct rejection */
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY;
	long fd = syscall(__NR_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how) - 4);
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "openat2 syscall (437)");
	}

	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects undersized struct open_how (-EINVAL)");
	} else {
		report_fail(mod, "Rejects undersized open_how", "fd=%ld errno=%d (%s)", fd, errno, strerror(errno));
		if (fd >= 0) close(fd);
	}

	/* 2. Happy Path: standard openat2 */
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC;
	fd = syscall(__NR_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
	if (fd >= 0) {
		report_pass(mod, "Standard openat2 on /dev/null");
		close(fd);
	} else {
		report_fail(mod, "Standard openat2", "fd=%ld errno=%d (%s)", fd, errno, strerror(errno));
	}

	/* 3. Edge Case: RESOLVE_BENEATH escapes must fail with -EXDEV */
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC;
	how.resolve = RESOLVE_BENEATH;
	int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
	if (dirfd >= 0) {
		fd = syscall(__NR_openat2, dirfd, "../etc/passwd", &how, sizeof(how));
		if (fd < 0 && errno == EXDEV) {
			report_pass(mod, "RESOLVE_BENEATH blocks path escape (-EXDEV)");
		} else {
			report_fail(mod, "RESOLVE_BENEATH path escape", "fd=%ld errno=%d (%s)", fd, errno, strerror(errno));
			if (fd >= 0) close(fd);
		}
		close(dirfd);
	}

	/* 4. Edge Case: RESOLVE_NO_SYMLINKS on symlink must fail with -ELOOP */
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC;
	how.resolve = RESOLVE_NO_SYMLINKS;
	fd = syscall(__NR_openat2, AT_FDCWD, "/proc/self", &how, sizeof(how));
	if (fd < 0 && errno == ELOOP) {
		report_pass(mod, "RESOLVE_NO_SYMLINKS blocks symlink traversal (-ELOOP)");
	} else {
		report_fail(mod, "RESOLVE_NO_SYMLINKS", "fd=%ld errno=%d (%s)", fd, errno, strerror(errno));
		if (fd >= 0) close(fd);
	}

	/* 5. Edge Case: RESOLVE_NO_MAGICLINKS on /proc/self/exe must fail with -ELOOP */
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC;
	how.resolve = RESOLVE_NO_MAGICLINKS;
	fd = syscall(__NR_openat2, AT_FDCWD, "/proc/self/exe", &how, sizeof(how));
	if (fd < 0 && errno == ELOOP) {
		report_pass(mod, "RESOLVE_NO_MAGICLINKS blocks magic link (/proc/self/exe) (-ELOOP)");
	} else {
		report_fail(mod, "RESOLVE_NO_MAGICLINKS", "fd=%ld errno=%d (%s)", fd, errno, strerror(errno));
		if (fd >= 0) close(fd);
	}

	/* 6. Edge Case: unknown resolve flag must fail with -EINVAL */
	memset(&how, 0, sizeof(how));
	how.flags = O_RDONLY | O_CLOEXEC;
	how.resolve = (1ULL << 60);
	fd = syscall(__NR_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "openat2 rejects unknown resolve flags (-EINVAL)");
	} else {
		report_fail(mod, "openat2 unknown resolve flags", "fd=%ld errno=%d", fd, errno);
		if (fd >= 0) close(fd);
	}
}

static void test_syscall_close_range(void)
{
	const char *mod = "SYS_CLOSE_RANGE";

	/* 1. Base Existence Check & first > last rejection */
	long ret = syscall(__NR_close_range, 100, 50, 0);
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "close_range syscall (436)");
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects first > last (-EINVAL)");
	} else {
		report_fail(mod, "Rejects first > last", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
	}

	/* 2. Edge Case: invalid flags */
	ret = syscall(__NR_close_range, 100, 105, 0xFFFFFFFFU);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects unknown close_range flags (-EINVAL)");
	} else {
		report_fail(mod, "Rejects unknown flags", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
	}

	/* 3. Happy Path: close range of open descriptors */
	int fd1 = open("/dev/null", O_RDONLY);
	int fd2 = open("/dev/null", O_RDONLY);
	int fd3 = open("/dev/null", O_RDONLY);
	if (fd1 >= 0 && fd2 >= 0 && fd3 >= 0) {
		int min_fd = fd1 < fd2 ? (fd1 < fd3 ? fd1 : fd3) : (fd2 < fd3 ? fd2 : fd3);
		int max_fd = fd1 > fd2 ? (fd1 > fd3 ? fd1 : fd3) : (fd2 > fd3 ? fd2 : fd3);

		ret = syscall(__NR_close_range, min_fd, max_fd, 0);
		if (ret == 0 && fcntl(fd1, F_GETFD) < 0 && fcntl(fd2, F_GETFD) < 0 && fcntl(fd3, F_GETFD) < 0)
			report_pass(mod, "Close allocated descriptor range [min..max]");
		else
			report_fail(mod, "Close descriptor range", "Failed: ret=%ld errno=%d", ret, errno);
	}

	/* 4. CLOSE_RANGE_CLOEXEC flag */
	int cfd = open("/dev/null", O_RDONLY);
	if (cfd >= 0) {
		ret = syscall(__NR_close_range, cfd, cfd, CLOSE_RANGE_CLOEXEC);
		int flags = fcntl(cfd, F_GETFD);
		if (ret == 0 && (flags & FD_CLOEXEC))
			report_pass(mod, "CLOSE_RANGE_CLOEXEC sets FD_CLOEXEC");
		else
			report_fail(mod, "CLOSE_RANGE_CLOEXEC", "ret=%ld flags=0x%x", ret, flags);
		close(cfd);
	}
}

static void test_syscall_faccessat2(void)
{
	const char *mod = "SYS_FACCESSAT2";

	/* 1. Base Existence Check & unknown flags */
	long ret = syscall(__NR_faccessat2, AT_FDCWD, "/dev/null", R_OK, 0xFFFFFFFFU);
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "faccessat2 syscall (439)");
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects unknown flags (-EINVAL)");
	} else {
		report_fail(mod, "Rejects unknown flags", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. Happy Path */
	ret = syscall(__NR_faccessat2, AT_FDCWD, "/dev/null", R_OK | W_OK, AT_EACCESS);
	if (ret == 0) {
		report_pass(mod, "faccessat2 check on /dev/null with AT_EACCESS");
	} else {
		report_fail(mod, "faccessat2 check", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
	}

	/* 3. AT_SYMLINK_NOFOLLOW on dangling symlink */
	const char *dangling_link = "/tmp/test_dangling_symlink_faccessat2";
	unlink(dangling_link);
	if (symlink("/tmp/nonexistent_faccessat2_target", dangling_link) == 0) {
		ret = syscall(__NR_faccessat2, AT_FDCWD, dangling_link, F_OK, AT_SYMLINK_NOFOLLOW);
		if (ret == 0) {
			report_pass(mod, "faccessat2 with AT_SYMLINK_NOFOLLOW detects dangling symlink");
		} else {
			report_fail(mod, "faccessat2 AT_SYMLINK_NOFOLLOW", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		}

		/* Without AT_SYMLINK_NOFOLLOW, must follow link and fail with -ENOENT */
		ret = syscall(__NR_faccessat2, AT_FDCWD, dangling_link, F_OK, 0);
		if (ret < 0 && errno == ENOENT) {
			report_pass(mod, "faccessat2 without AT_SYMLINK_NOFOLLOW follows to missing target (-ENOENT)");
		} else {
			report_fail(mod, "faccessat2 follow dangling symlink", "ret=%ld errno=%d", ret, errno);
		}
		unlink(dangling_link);
	}
}

static void test_syscall_epoll_pwait2(void)
{
	const char *mod = "SYS_EPOLL_PWAIT2";

	int epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		report_fail(mod, "epoll_create1", "errno=%d", errno);
		return;
	}

	struct epoll_event ev;
	struct timespec ts;

	/* 1. Base Existence Check & tv_nsec >= 1e9 */
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000000L;
	long ret = syscall(__NR_epoll_pwait2, epfd, &ev, 1, &ts, NULL, (size_t)0);
	if (ret < 0 && errno == ENOSYS) {
		close(epfd);
		CHECK_BASE_OR_SKIP(false, mod, "epoll_pwait2 syscall (441)");
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects tv_nsec >= 1,000,000,000 (-EINVAL)");
	} else {
		report_fail(mod, "Rejects invalid tv_nsec", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. Negative tv_nsec */
	ts.tv_nsec = -1;
	ret = syscall(__NR_epoll_pwait2, epfd, &ev, 1, &ts, NULL, (size_t)0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects negative tv_nsec (-EINVAL)");
	} else {
		report_fail(mod, "Rejects negative tv_nsec", "ret=%ld errno=%d", ret, errno);
	}

	/* 3. maxevents <= 0 */
	ts.tv_sec = 0;
	ts.tv_nsec = 1000;
	ret = syscall(__NR_epoll_pwait2, epfd, &ev, 0, &ts, NULL, (size_t)0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects maxevents <= 0 (-EINVAL)");
	} else {
		report_fail(mod, "Rejects maxevents <= 0", "ret=%ld errno=%d", ret, errno);
	}

	/* 4. Valid timeout (50ms) */
	ts.tv_sec = 0;
	ts.tv_nsec = 50000000L; /* 50ms */
	int retries = 5;
	do {
		ret = syscall(__NR_epoll_pwait2, epfd, &ev, 1, &ts, NULL, (size_t)0);
	} while (ret < 0 && errno == EINTR && --retries > 0);

	if (ret == 0) {
		report_pass(mod, "epoll_pwait2 timed out cleanly after 50ms");
	} else if (ret < 0 && errno == EINTR) {
		report_pass(mod, "epoll_pwait2 interrupted by signal (-EINTR)");
	} else {
		report_fail(mod, "epoll_pwait2 timeout", "ret=%ld errno=%d", ret, errno);
	}

	close(epfd);
}

static void test_syscall_rseq(void)
{
	const char *mod = "SYS_RSEQ";
	static struct rseq_local rs;
	memset(&rs, 0, sizeof(rs));

	/* 1. Base Existence Check & invalid length */
	long ret = syscall(__NR_rseq, &rs, 12, 0, RSEQ_SIG);
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "rseq syscall (293)");
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects invalid rseq_len (-EINVAL)");
	} else {
		report_fail(mod, "Rejects invalid rseq_len", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
	}

	/* 2. Valid registration */
	ret = syscall(__NR_rseq, &rs, sizeof(rs), 0, RSEQ_SIG);
	if (ret == 0) {
		report_pass(mod, "Register rseq for current thread");

		/* Double registration must fail with -EBUSY */
		long ret2 = syscall(__NR_rseq, &rs, sizeof(rs), 0, RSEQ_SIG);
		if (ret2 < 0 && errno == EBUSY)
			report_pass(mod, "Double registration fails with -EBUSY");
		else
			report_fail(mod, "Double registration", "ret=%ld errno=%d", ret2, errno);

		/* Unregister */
		long unreg = syscall(__NR_rseq, &rs, sizeof(rs), RSEQ_FLAG_UNREGISTER, RSEQ_SIG);
		if (unreg == 0)
			report_pass(mod, "Unregister rseq");
		else
			report_fail(mod, "Unregister rseq", "ret=%ld errno=%d", unreg, errno);
	} else if (errno == EBUSY) {
		report_pass(mod, "rseq already registered by C library runtime (-EBUSY)");
	} else {
		report_fail(mod, "Register rseq", "errno=%d (%s)", errno, strerror(errno));
	}
}

static void test_syscall_pidfd(void)
{
	const char *mod = "SYS_PIDFD";

	/* 1. Base Existence Check */
	int pfd = syscall(__NR_pidfd_open, getpid(), 0);
	if (pfd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "pidfd syscalls (424/434/438)");
	}

	if (pfd >= 0) {
		report_pass(mod, "pidfd_open for getpid()");

		/* 2. pidfd_send_signal alive check (sig=0) */
		long sig_ret = syscall(__NR_pidfd_send_signal, pfd, 0, NULL, 0);
		if (sig_ret == 0)
			report_pass(mod, "pidfd_send_signal with sig=0 (alive check)");
		else
			report_fail(mod, "pidfd_send_signal", "ret=%ld errno=%d (%s)", sig_ret, errno, strerror(errno));

		/* 3. pidfd_getfd dup target descriptor (dup stdin) */
		int dup_fd = syscall(__NR_pidfd_getfd, pfd, 0, 0);
		if (dup_fd >= 0) {
			report_pass(mod, "pidfd_getfd duplicate target descriptor");
			close(dup_fd);
		} else {
			report_fail(mod, "pidfd_getfd", "ret=%d errno=%d (%s)", dup_fd, errno, strerror(errno));
		}

		/* 4. pidfd_send_signal invalid signal */
		long bad_sig = syscall(__NR_pidfd_send_signal, pfd, 99999, NULL, 0);
		if (bad_sig < 0 && errno == EINVAL) {
			report_pass(mod, "pidfd_send_signal rejects invalid signal (-EINVAL)");
		} else {
			report_fail(mod, "pidfd_send_signal invalid signal", "ret=%ld errno=%d", bad_sig, errno);
		}

		/* 5. pidfd_send_signal invalid flags */
		bad_sig = syscall(__NR_pidfd_send_signal, pfd, 0, NULL, 0xFFFFFFFFU);
		if (bad_sig < 0 && errno == EINVAL) {
			report_pass(mod, "pidfd_send_signal rejects invalid flags (-EINVAL)");
		} else {
			report_fail(mod, "pidfd_send_signal invalid flags", "ret=%ld errno=%d", bad_sig, errno);
		}

		/* 6. pidfd_getfd invalid flags */
		int bad_dup = syscall(__NR_pidfd_getfd, pfd, 0, 0xFFFFFFFFU);
		if (bad_dup < 0 && errno == EINVAL) {
			report_pass(mod, "pidfd_getfd rejects invalid flags (-EINVAL)");
		} else {
			report_fail(mod, "pidfd_getfd invalid flags", "ret=%d errno=%d", bad_dup, errno);
			if (bad_dup >= 0) close(bad_dup);
		}

		/* 7. pidfd_getfd invalid target fd */
		bad_dup = syscall(__NR_pidfd_getfd, pfd, -1, 0);
		if (bad_dup < 0 && errno == EBADF) {
			report_pass(mod, "pidfd_getfd rejects invalid target fd (-EBADF)");
		} else {
			report_fail(mod, "pidfd_getfd invalid target fd", "ret=%d errno=%d", bad_dup, errno);
			if (bad_dup >= 0) close(bad_dup);
		}

		close(pfd);
	} else {
		report_fail(mod, "pidfd_open self", "errno=%d (%s)", errno, strerror(errno));
	}

	/* 4. pidfd_open rejects invalid pid */
	pfd = syscall(__NR_pidfd_open, -1, 0);
	if (pfd < 0 && (errno == EINVAL || errno == ESRCH)) {
		report_pass(mod, "pidfd_open rejects pid=-1 (-EINVAL/-ESRCH)");
	} else {
		report_fail(mod, "pidfd_open invalid pid", "pfd=%d errno=%d", pfd, errno);
		if (pfd >= 0) close(pfd);
	}
}

static void run_syscalls_core_suite(void)
{
	test_syscall_clone3();
	test_syscall_openat2();
	test_syscall_close_range();
	test_syscall_faccessat2();
	test_syscall_epoll_pwait2();
	test_syscall_rseq();
	test_syscall_pidfd();
}

void register_suite_syscalls_core(void)
{
	register_test_suite("syscalls_core", "Core Modern Syscalls (clone3, openat2, close_range, faccessat2, epoll_pwait2, rseq, pidfd)", run_syscalls_core_suite);
}
