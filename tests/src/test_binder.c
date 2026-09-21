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
		report_fail(mod, "BINDER_VERSION", "ret=%d version=%d (expected %d) errno=%d",
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

static void test_binder_oneway_spam_detection(int fd)
{
	const char *mod = "BINDER_SPAM";
	uint32_t enable = 1;

	int ret = ioctl(fd, BINDER_ENABLE_ONEWAY_SPAM_DETECTION_LOCAL, &enable);
	if (ret == 0) {
		report_pass(mod, "BINDER_ENABLE_ONEWAY_SPAM_DETECTION enable succeeds");
	} else {
		report_fail(mod, "Enable oneway spam detection", "ret=%d errno=%d (%s)",
			    ret, errno, strerror(errno));
	}

	enable = 0;
	ret = ioctl(fd, BINDER_ENABLE_ONEWAY_SPAM_DETECTION_LOCAL, &enable);
	if (ret == 0) {
		report_pass(mod, "BINDER_ENABLE_ONEWAY_SPAM_DETECTION disable succeeds");
	} else {
		report_fail(mod, "Disable oneway spam detection", "ret=%d errno=%d (%s)",
			    ret, errno, strerror(errno));
	}

	/* NULL pointer must fail */
	ret = ioctl(fd, BINDER_ENABLE_ONEWAY_SPAM_DETECTION_LOCAL, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		report_pass(mod, "BINDER_ENABLE_ONEWAY_SPAM_DETECTION rejects NULL pointer (-EFAULT/-EINVAL)");
	} else {
		report_fail(mod, "Spam detection NULL pointer", "ret=%d errno=%d", ret, errno);
	}
}

static void test_binder_freezer(int fd)
{
	const char *mod = "BINDER_FREEZER";
	struct binder_frozen_status_info_local status;
	memset(&status, 0, sizeof(status));
	status.pid = (uint32_t)getpid();

	int ret = ioctl(fd, BINDER_GET_FROZEN_INFO_LOCAL, &status);
	if (ret == 0) {
		report_pass(mod, "BINDER_GET_FROZEN_INFO queries process freezer status");
	} else {
		report_fail(mod, "BINDER_GET_FROZEN_INFO query self", "ret=%d errno=%d (%s)",
			    ret, errno, strerror(errno));
	}

	/* NULL pointer must fail */
	ret = ioctl(fd, BINDER_GET_FROZEN_INFO_LOCAL, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		report_pass(mod, "BINDER_GET_FROZEN_INFO rejects NULL pointer (-EFAULT/-EINVAL)");
	} else {
		report_fail(mod, "Frozen info NULL pointer", "ret=%d errno=%d", ret, errno);
	}

	/* Freeze non-existent PID should fail with -EINVAL */
	struct binder_freeze_info_local freeze;
	memset(&freeze, 0, sizeof(freeze));
	freeze.pid = 0x7FFFFFFF;
	freeze.enable = 1;
	freeze.timeout_ms = 100;

	ret = ioctl(fd, BINDER_FREEZE_LOCAL, &freeze);
	if (ret < 0 && (errno == EINVAL || errno == ESRCH)) {
		report_pass(mod, "BINDER_FREEZE on non-existent PID rejected (-EINVAL/-ESRCH)");
	} else {
		report_fail(mod, "BINDER_FREEZE non-existent PID", "ret=%d errno=%d", ret, errno);
	}

	ret = ioctl(fd, BINDER_FREEZE_LOCAL, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		report_pass(mod, "BINDER_FREEZE rejects NULL pointer (-EFAULT/-EINVAL)");
	} else {
		report_fail(mod, "Binder freeze NULL pointer", "ret=%d errno=%d", ret, errno);
	}
}

static void test_binder_extended_error(int fd)
{
	const char *mod = "BINDER_EXT_ERROR";
	struct binder_extended_error_local ee;
	memset(&ee, 0xFF, sizeof(ee));

	int ret = ioctl(fd, BINDER_GET_EXTENDED_ERROR_LOCAL, &ee);
	if (ret == 0 && ee.id == 0 && (ee.command == 0 || ee.command == BR_OK_LOCAL)) {
		report_pass(mod, "BINDER_GET_EXTENDED_ERROR retrieves default clean state");
	} else {
		report_fail(mod, "BINDER_GET_EXTENDED_ERROR query", "ret=%d id=%u cmd=%u param=%d errno=%d",
			    ret, ee.id, ee.command, ee.param, errno);
	}

	ret = ioctl(fd, BINDER_GET_EXTENDED_ERROR_LOCAL, NULL);
	if (ret < 0 && (errno == EFAULT || errno == EINVAL)) {
		report_pass(mod, "BINDER_GET_EXTENDED_ERROR rejects NULL pointer (-EFAULT/-EINVAL)");
	} else {
		report_fail(mod, "Extended error NULL pointer", "ret=%d errno=%d", ret, errno);
	}
}

static void test_binderfs_features(void)
{
	const char *mod = "BINDERFS_FEATURES";
	const char *feat_spam = "/dev/binderfs/features/oneway_spam_detection";
	const char *feat_ext = "/dev/binderfs/features/extended_error";

	int fd = open(feat_spam, O_RDONLY);
	if (fd >= 0) {
		char buf[16] = {0};
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0 && buf[0] == '1') {
			report_pass(mod, "binderfs features/oneway_spam_detection is enabled ('1')");
		} else {
			report_fail(mod, "read oneway_spam_detection", "n=%zd buf='%s'", n, buf);
		}
	} else {
		report_pass(mod, "binderfs features/oneway_spam_detection (checked/optional)");
	}

	fd = open(feat_ext, O_RDONLY);
	if (fd >= 0) {
		char buf[16] = {0};
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0 && buf[0] == '1') {
			report_pass(mod, "binderfs features/extended_error is enabled ('1')");
		} else {
			report_fail(mod, "read extended_error", "n=%zd buf='%s'", n, buf);
		}
	} else {
		report_pass(mod, "binderfs features/extended_error (checked/optional)");
	}
}

static void run_binder_suite(void)
{
	int fd = open_binder_device();
	if (fd < 0) {
		CHECK_BASE_OR_SKIP(false, "BINDER", "Binder IPC Driver (/dev/binder)");
	}

	test_binder_version(fd);
	test_binder_max_threads(fd);
	test_binder_oneway_spam_detection(fd);
	test_binder_freezer(fd);
	test_binder_extended_error(fd);
	close(fd);

	test_binder_mmap_semantics();
	test_binder_write_read_loopers();
	test_binderfs_features();
}

void register_suite_binder(void)
{
	register_test_suite("binder", "Binder IPC Subsystem (Protocol Version 8, Max Threads, MMAP Semantics, Looper State, Freezer, Spam Detection, Extended Error)", run_binder_suite);
}
