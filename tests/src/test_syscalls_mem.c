#include "test_framework.h"
#include "test_uapi.h"
#include <sys/uio.h>
#include <sys/mman.h>

static void test_syscall_process_madvise(void)
{
	const char *mod = "SYS_PROC_MADV";
	void *addr = mmap(NULL, 4096 * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		report_fail(mod, "mmap buffer setup", "errno=%d", errno);
		return;
	}
	memset(addr, 0x55, 4096 * 4);

	struct iovec iov = {
		.iov_base = addr,
		.iov_len  = 4096 * 4,
	};

	int pidfd = syscall(__NR_pidfd_open, getpid(), 0);
	if (pidfd >= 0) {
		/* 1. Base Existence Check & non-zero flags */
		long ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_COLD, 0xFFFFFFFFU);
		if (ret < 0 && errno == ENOSYS) {
			close(pidfd);
			munmap(addr, 4096 * 4);
			CHECK_BASE_OR_SKIP(false, mod, "process_madvise syscall (440)");
		}

		if (ret < 0 && errno == EINVAL) {
			report_pass(mod, "Rejects non-zero flags (-EINVAL)");
		} else {
			report_fail(mod, "Rejects non-zero flags", "ret=%ld errno=%d", ret, errno);
		}

		/* 2. Invalid advice */
		ret = syscall(__NR_process_madvise, pidfd, &iov, 1, 99999, 0);
		if (ret < 0 && errno == EINVAL) {
			report_pass(mod, "Rejects invalid advice (-EINVAL)");
		} else {
			report_fail(mod, "Rejects invalid advice", "ret=%ld errno=%d", ret, errno);
		}

		/* 3. Valid call: MADV_COLD on self */
		ret = syscall(__NR_process_madvise, pidfd, &iov, 1, MADV_COLD, 0);
		if (ret >= 0) {
			report_pass(mod, "process_madvise MADV_COLD on self");
		} else {
			report_fail(mod, "process_madvise MADV_COLD", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		}

		close(pidfd);
	} else {
		report_fail(mod, "pidfd_open self", "errno=%d", errno);
	}

	munmap(addr, 4096 * 4);
}

static void test_syscall_process_mrelease(void)
{
	const char *mod = "SYS_PROC_MREL";

	int pidfd = syscall(__NR_pidfd_open, getpid(), 0);
	if (pidfd >= 0) {
		/* 1. Base Existence Check & non-zero flags */
		long ret = syscall(__NR_process_mrelease, pidfd, 0xFFFFFFFFU);
		if (ret < 0 && errno == ENOSYS) {
			close(pidfd);
			CHECK_BASE_OR_SKIP(false, mod, "process_mrelease syscall (448)");
		}

		if (ret < 0 && errno == EINVAL) {
			report_pass(mod, "Rejects non-zero flags (-EINVAL)");
		} else {
			report_fail(mod, "Rejects non-zero flags", "ret=%ld errno=%d", ret, errno);
		}

		/* 2. Releasing living process must be rejected */
		ret = syscall(__NR_process_mrelease, pidfd, 0);
		if (ret < 0 && (errno == EINVAL || errno == ESRCH || errno == EBUSY)) {
			report_pass(mod, "Rejects releasing memory of living process (-EINVAL/-ESRCH/-EBUSY)");
		} else {
			report_fail(mod, "Rejects living process release", "ret=%ld errno=%d", ret, errno);
		}

		close(pidfd);
	} else {
		report_fail(mod, "pidfd_open self", "errno=%d", errno);
	}
}

static void test_syscall_memfd_secret(void)
{
	const char *mod = "SYS_MEMFD_SEC";

	/* 1. Base Existence Check & invalid flags */
	long fd = syscall(__NR_memfd_secret, 0xFFFFFFFFU);
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "memfd_secret syscall (447)");
	}

	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "memfd_secret rejects unknown flags (-EINVAL)");
	} else {
		report_fail(mod, "memfd_secret flags", "ret=%ld errno=%d", fd, errno);
		if (fd >= 0) close(fd);
	}

	/* 2. Happy Path */
	fd = syscall(__NR_memfd_secret, 0);
	if (fd >= 0) {
		report_pass(mod, "Create memfd_secret file descriptor");
		if (ftruncate(fd, 4096) == 0) {
			void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			if (ptr != MAP_FAILED) {
				memset(ptr, 0x5A, 4096);
				if (((uint8_t *)ptr)[0] == 0x5A)
					report_pass(mod, "Write & verify secret memory page");
				else
					report_fail(mod, "Secret page verification", "Data mismatch");
				munmap(ptr, 4096);
			}
		}
		close(fd);
	} else {
		report_fail(mod, "Create memfd_secret", "errno=%d (%s)", errno, strerror(errno));
	}
}

static void test_syscall_set_mempolicy_home_node(void)
{
	const char *mod = "SYS_HOMENODE";
	void *addr = mmap(NULL, 4096 * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		report_fail(mod, "mmap buffer setup", "errno=%d", errno);
		return;
	}

	/* 1. Base Existence Check & invalid flags */
	long ret = syscall(__NR_set_mempolicy_home_node, (unsigned long)addr, 4096, 0, 0xFFFFFFFFU);
	if (ret < 0 && errno == ENOSYS) {
		munmap(addr, 4096 * 2);
		CHECK_BASE_OR_SKIP(false, mod, "set_mempolicy_home_node syscall (450)");
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "set_mempolicy_home_node rejects invalid flags (-EINVAL)");
	} else {
		report_fail(mod, "home_node invalid flags", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. Unaligned start address */
	ret = syscall(__NR_set_mempolicy_home_node, (unsigned long)addr + 123, 4096, 0, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "set_mempolicy_home_node rejects unaligned start (-EINVAL)");
	} else {
		report_fail(mod, "home_node unaligned start", "ret=%ld errno=%d", ret, errno);
	}

	/* 3. Out-of-range home_node */
	ret = syscall(__NR_set_mempolicy_home_node, (unsigned long)addr, 4096, 99999UL, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "set_mempolicy_home_node rejects out-of-range node (-EINVAL)");
	} else {
		report_fail(mod, "home_node out-of-range node", "ret=%ld errno=%d", ret, errno);
	}

	/* 4. Address overflow */
	ret = syscall(__NR_set_mempolicy_home_node, 0xFFFFFFFFFFFFF000UL, 0x2000, 0, 0);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "set_mempolicy_home_node rejects address overflow (-EINVAL)");
	} else {
		report_fail(mod, "home_node address overflow", "ret=%ld errno=%d", ret, errno);
	}

	/* 5. Length zero */
	ret = syscall(__NR_set_mempolicy_home_node, (unsigned long)addr, 0, 0, 0);
	if (ret == 0) {
		report_pass(mod, "set_mempolicy_home_node handles len=0 (returns 0)");
	} else {
		report_fail(mod, "home_node len=0", "ret=%ld errno=%d", ret, errno);
	}

	munmap(addr, 4096 * 2);
}

static void run_syscalls_mem_suite(void)
{
	test_syscall_process_madvise();
	test_syscall_process_mrelease();
	test_syscall_memfd_secret();
	test_syscall_set_mempolicy_home_node();
}

void register_suite_syscalls_mem(void)
{
	register_test_suite("syscalls_mem", "Memory Management Syscalls (process_madvise, process_mrelease, memfd_secret, set_mempolicy_home_node)", run_syscalls_mem_suite);
}
