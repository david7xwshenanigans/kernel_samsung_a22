#include "test_framework.h"
#include "test_uapi.h"
#include <fcntl.h>
#include <sys/mman.h>

static int open_binder_device(void)
{
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fd = open("/dev/hwbinder", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fd = open("/dev/vndbinder", O_RDWR | O_CLOEXEC);
	return fd;
}

static void test_binder_version(int fd)
{
	const char *mod = "BINDER_VERSION";
	struct binder_version_local ver;
	memset(&ver, 0, sizeof(ver));

	int ret = ioctl(fd, BINDER_VERSION_LOCAL, &ver);
	if (ret == 0 && ver.protocol_version == BINDER_CURRENT_PROTOCOL_VERSION) {
		report_pass(mod, "BINDER_VERSION returns protocol version 8");
	} else {
		report_fail(mod, "BINDER_VERSION", "ret=%d version=%ld (expected %d) errno=%d",
			    ret, ver.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION, errno);
	}

	/* NULL pointer must return error (-EFAULT or -EINVAL) */
	ret = ioctl(fd, BINDER_VERSION_LOCAL, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		report_pass(mod, "BINDER_VERSION rejects NULL pointer (-EFAULT/-EINVAL)");
	} else {
		report_fail(mod, "BINDER_VERSION NULL pointer", "ret=%d errno=%d", ret, errno);
	}
}

static void test_binder_max_threads(int fd)
{
	const char *mod = "BINDER_THREADS";
	uint32_t max_threads = 15;

	int ret = ioctl(fd, BINDER_SET_MAX_THREADS_LOCAL, &max_threads);
	if (ret == 0) {
		report_pass(mod, "BINDER_SET_MAX_THREADS sets thread pool limit");
	} else {
		report_fail(mod, "BINDER_SET_MAX_THREADS", "ret=%d errno=%d", ret, errno);
	}

	/* NULL pointer must return -EINVAL or -EFAULT */
	ret = ioctl(fd, BINDER_SET_MAX_THREADS_LOCAL, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		report_pass(mod, "BINDER_SET_MAX_THREADS rejects NULL pointer (-EFAULT/-EINVAL)");
	} else {
		report_fail(mod, "BINDER_SET_MAX_THREADS NULL pointer", "ret=%d errno=%d", ret, errno);
	}
}

static void test_binder_mmap_semantics(void)
{
	const char *mod = "BINDER_MMAP";
	int fd = open_binder_device();
	if (fd < 0) {
		report_fail(mod, "open binder", "Failed to open device: errno=%d", errno);
		return;
	}

	/* 1. PROT_WRITE must be rejected with -EPERM */
	void *ptr_rw = mmap(NULL, 128 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (ptr_rw == MAP_FAILED && errno == EPERM) {
		report_pass(mod, "Rejects writable mmap on binder fd (-EPERM)");
	} else {
		report_fail(mod, "Writable mmap rejection", "ptr=%p errno=%d", ptr_rw, errno);
		if (ptr_rw != MAP_FAILED) munmap(ptr_rw, 128 * 1024);
	}

	/* 2. PROT_READ must succeed */
	void *ptr_ro = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ptr_ro != MAP_FAILED) {
		report_pass(mod, "PROT_READ mmap allocates transaction buffer");

		/* 3. Second mmap on same fd must fail with -EBUSY */
		void *ptr_second = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE, fd, 0);
		if (ptr_second == MAP_FAILED && errno == EBUSY) {
			report_pass(mod, "Duplicate mmap rejected (-EBUSY)");
		} else {
			report_fail(mod, "Duplicate mmap", "ptr=%p errno=%d", ptr_second, errno);
			if (ptr_second != MAP_FAILED) munmap(ptr_second, 128 * 1024);
		}

		munmap(ptr_ro, 128 * 1024);
	} else {
		report_fail(mod, "PROT_READ mmap", "errno=%d (%s)", errno, strerror(errno));
	}

	close(fd);
}

static void test_binder_write_read_loopers(void)
{
	const char *mod = "BINDER_WRITE_READ";
	int fd = open_binder_device();
	if (fd < 0) {
		report_fail(mod, "open binder", "Failed to open device: errno=%d", errno);
		return;
	}

	/* Must map buffer before performing transactions */
	void *map = mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		report_fail(mod, "mmap binder buffer", "errno=%d", errno);
		close(fd);
		return;
	}

	/* 1. Zero write/read size (noop) */
	struct binder_write_read_local bwr;
	memset(&bwr, 0, sizeof(bwr));
	int ret = ioctl(fd, BINDER_WRITE_READ_LOCAL, &bwr);
	if (ret == 0) {
		report_pass(mod, "Zero-length BINDER_WRITE_READ noop succeeds");
	} else {
		report_fail(mod, "Zero-length BINDER_WRITE_READ", "ret=%d errno=%d", ret, errno);
	}

	/* 2. BC_ENTER_LOOPER */
	uint32_t cmd = BC_ENTER_LOOPER_LOCAL;
	memset(&bwr, 0, sizeof(bwr));
	bwr.write_size = sizeof(cmd);
	bwr.write_consumed = 0;
	bwr.write_buffer = (uintptr_t)&cmd;
	ret = ioctl(fd, BINDER_WRITE_READ_LOCAL, &bwr);
	if (ret == 0 && bwr.write_consumed == sizeof(cmd)) {
		report_pass(mod, "BC_ENTER_LOOPER successfully registered");
	} else {
		report_fail(mod, "BC_ENTER_LOOPER", "ret=%d consumed=%llu errno=%d",
			    ret, (unsigned long long)bwr.write_consumed, errno);
	}

	/* 3. BC_EXIT_LOOPER */
	cmd = BC_EXIT_LOOPER_LOCAL;
	memset(&bwr, 0, sizeof(bwr));
	bwr.write_size = sizeof(cmd);
	bwr.write_consumed = 0;
	bwr.write_buffer = (uintptr_t)&cmd;
	ret = ioctl(fd, BINDER_WRITE_READ_LOCAL, &bwr);
	if (ret == 0 && bwr.write_consumed == sizeof(cmd)) {
		report_pass(mod, "BC_EXIT_LOOPER successfully deregistered");
	} else {
		report_fail(mod, "BC_EXIT_LOOPER", "ret=%d consumed=%llu errno=%d",
			    ret, (unsigned long long)bwr.write_consumed, errno);
	}

	munmap(map, 128 * 1024);
	close(fd);
}

static void run_binder_suite(void)
{
	int fd = open_binder_device();
	if (fd < 0) {
		CHECK_BASE_OR_SKIP(false, "BINDER", "Binder IPC Driver (/dev/binder)");
	}

	test_binder_version(fd);
	test_binder_max_threads(fd);
	close(fd);

	test_binder_mmap_semantics();
	test_binder_write_read_loopers();
}

void register_suite_binder(void)
{
	register_test_suite("binder", "Binder IPC Subsystem (Protocol Version 8, Max Threads, MMAP Semantics, Looper State)", run_binder_suite);
}
