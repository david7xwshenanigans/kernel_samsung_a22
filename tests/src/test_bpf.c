#include "test_framework.h"
#include "test_uapi.h"
#include <sys/mman.h>

static void test_bpf_bloom_filter(void)
{
	const char *mod = "BPF_BLOOM";
	union bpf_attr_local attr;

	/* 1. Base Existence Check & key_size check */
	memset(&attr, 0, sizeof(attr));
	attr.map_type    = BPF_MAP_TYPE_BLOOM_FILTER;
	attr.key_size    = 4; /* Invalid: Bloom filter MUST have key_size == 0 */
	attr.value_size  = 8;
	attr.max_entries = 1024;
	attr.map_extra   = 3; /* 3 hash functions */

	int fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "BPF Bloom Filter map");
	}

	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects non-zero key_size (-EINVAL)");
	} else if (fd >= 0) {
		close(fd);
		report_fail(mod, "Rejects non-zero key_size", "Unexpected success creating map fd=%d", fd);
		return;
	} else if (errno == EPERM) {
		report_skip(mod, "Rejects non-zero key_size", "CAP_BPF/CAP_SYS_ADMIN required");
		return;
	} else {
		report_fail(mod, "Rejects non-zero key_size", "errno=%d (%s)", errno, strerror(errno));
		return;
	}

	/* 2. Valid creation */
	attr.key_size = 0;
	attr.map_extra = 4;
	fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0) {
		if (errno == EPERM) {
			report_skip(mod, "Create Bloom Filter", "CAP_BPF/CAP_SYS_ADMIN required");
			return;
		}
		report_fail(mod, "Create Bloom Filter", "sys_bpf failed: %s (errno=%d)", strerror(errno), errno);
		return;
	}
	report_pass(mod, "Create Bloom Filter (key_size=0, extra_hashes=4)");

	/* 3. Insert and Lookup */
	uint64_t val = 0xDEADBEEFCAFE0001ULL;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.value  = (uint64_t)(uintptr_t)&val;
	int ret = sys_bpf(BPF_CMD_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if (ret == 0) {
		report_pass(mod, "Update Bloom Filter element");
	} else {
		report_fail(mod, "Update Bloom Filter element", "Failed: %s", strerror(errno));
	}

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.value  = (uint64_t)(uintptr_t)&val;
	ret = sys_bpf(BPF_CMD_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
	if (ret == 0) {
		report_pass(mod, "Lookup inserted element (No false negative)");
	} else {
		report_fail(mod, "Lookup inserted element", "errno=%d (%s)", errno, strerror(errno));
	}

	/* 4. Deletion rejection */
	ret = sys_bpf(BPF_CMD_MAP_DELETE_ELEM, &attr, sizeof(attr));
	if (ret < 0 && (errno == EINVAL || errno == ENOTSUP)) {
		report_pass(mod, "Rejects delete operation on bloom filter");
	} else {
		report_fail(mod, "Rejects delete operation", "ret=%d errno=%d", ret, errno);
	}

	close(fd);
}

static void test_bpf_user_ringbuf(void)
{
	const char *mod = "BPF_USER_RBUF";
	union bpf_attr_local attr;

	/* 1. Base Existence Check & non-power-of-2 max_entries check */
	memset(&attr, 0, sizeof(attr));
	attr.map_type    = BPF_MAP_TYPE_USER_RINGBUF;
	attr.key_size    = 0;
	attr.value_size  = 0;
	attr.max_entries = 3000; /* Invalid: must be power of 2 and page-aligned */

	int fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "BPF User Ringbuf map");
	}

	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects non-power-of-2 max_entries (-EINVAL)");
	} else if (fd >= 0) {
		close(fd);
		report_fail(mod, "Rejects non-power-of-2", "Created map with invalid size, fd=%d", fd);
		return;
	} else if (errno == EPERM) {
		report_skip(mod, "Rejects non-power-of-2", "CAP_BPF/CAP_SYS_ADMIN required");
		return;
	} else {
		report_fail(mod, "Rejects non-power-of-2", "errno=%d (%s)", errno, strerror(errno));
		return;
	}

	/* 2. Valid creation: 4096 bytes (1 page) */
	attr.max_entries = 4096;
	fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0) {
		if (errno == EPERM) {
			report_skip(mod, "Create User Ringbuf", "CAP_BPF/CAP_SYS_ADMIN required");
			return;
		}
		report_fail(mod, "Create User Ringbuf", "Failed: %s (errno=%d)", strerror(errno), errno);
		return;
	}
	report_pass(mod, "Create User Ringbuf map (max_entries=4096)");

	/* 3. Memory-map verification:
	 * Page 0 (offset 0) is consumer page -> must be read-only (PROT_READ).
	 * Mapping page 0 with PROT_WRITE must fail with -EPERM.
	 * Producer page (offset 4096) can be mapped PROT_READ | PROT_WRITE.
	 */
	void *ptr_wr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr_wr == MAP_FAILED && errno == EPERM) {
		report_pass(mod, "Rejects writable mmap of consumer page at offset 0 (-EPERM)");
	} else {
		report_fail(mod, "Rejects writable mmap of consumer page", "ptr=%p errno=%d (%s)", ptr_wr, errno, strerror(errno));
		if (ptr_wr != MAP_FAILED) munmap(ptr_wr, 4096);
	}

	void *ptr_ro = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr_ro != MAP_FAILED) {
		report_pass(mod, "mmap consumer page (offset 0) with PROT_READ");
		munmap(ptr_ro, 4096);
	} else {
		report_fail(mod, "mmap consumer page with PROT_READ", "errno=%d (%s)", errno, strerror(errno));
	}

	void *ptr_prod = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096);
	if (ptr_prod != MAP_FAILED) {
		report_pass(mod, "mmap producer page (offset 4096) with PROT_READ | PROT_WRITE");
		munmap(ptr_prod, 4096);
	} else {
		report_fail(mod, "mmap producer page with PROT_READ | PROT_WRITE", "errno=%d (%s)", errno, strerror(errno));
	}

	close(fd);
}

static void test_bpf_task_storage(void)
{
	const char *mod = "BPF_TASK_STOR";
	union bpf_attr_local attr;

	/* 1. Base Existence Check & key_size check */
	memset(&attr, 0, sizeof(attr));
	attr.map_type    = BPF_MAP_TYPE_TASK_STORAGE;
	attr.key_size    = 8; /* Invalid: task storage key_size must be sizeof(int) = 4 */
	attr.value_size  = 64;
	attr.max_entries = 0;
	attr.map_flags   = BPF_F_NO_PREALLOC;

	int fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "BPF Task Storage map");
	}

	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects key_size != 4 (-EINVAL)");
	} else if (fd >= 0) {
		close(fd);
		report_fail(mod, "Rejects key_size != 4", "Created with invalid key_size, fd=%d", fd);
	} else if (errno == EPERM) {
		report_skip(mod, "Task storage key_size check", "CAP_BPF/CAP_SYS_ADMIN required");
	} else {
		report_fail(mod, "Task storage key_size check", "errno=%d (%s)", errno, strerror(errno));
	}

	/* 2. BTF requirement */
	attr.key_size = 4;
	attr.btf_key_type_id = 0;
	attr.btf_value_type_id = 0;
	fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "Enforces BTF requirements for Task Storage (-EINVAL)");
	} else if (fd >= 0) {
		close(fd);
		report_fail(mod, "BTF requirement", "Created without BTF unexpectedly, fd=%d", fd);
	} else if (errno == EPERM) {
		report_skip(mod, "BTF requirement", "CAP_BPF/CAP_SYS_ADMIN required");
	} else {
		report_fail(mod, "BTF requirement", "errno=%d (%s)", errno, strerror(errno));
	}
}

static void test_bpf_syscall_prog(void)
{
	const char *mod = "BPF_PROG_SYSCALL";
	struct bpf_insn_local insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	char log_buf[1024];
	memset(log_buf, 0, sizeof(log_buf));

	union bpf_attr_local attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type  = BPF_PROG_TYPE_SYSCALL;
	attr.prog_flags = 1U << 4; /* BPF_F_SLEEPABLE */
	attr.insn_cnt   = sizeof(insns) / sizeof(insns[0]);
	attr.insns     = (uint64_t)(uintptr_t)insns;
	attr.license   = (uint64_t)(uintptr_t)"GPL";
	attr.log_buf   = (uint64_t)(uintptr_t)log_buf;
	attr.log_size  = sizeof(log_buf);
	attr.log_level = 1;

	int fd = sys_bpf(BPF_CMD_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "BPF Syscall Program type");
	}

	if (fd >= 0) {
		report_pass(mod, "Load BPF_PROG_TYPE_SYSCALL program");
		close(fd);
	} else if (errno == EPERM) {
		report_skip(mod, "Load BPF_PROG_TYPE_SYSCALL", "Privileged BPF required");
	} else {
		report_fail(mod, "Load BPF_PROG_TYPE_SYSCALL", "errno=%d (%s) log: %s", errno, strerror(errno), log_buf);
	}
}

static void test_bpf_ktime_tai_helper(void)
{
	const char *mod = "BPF_KTIME_TAI";
	struct bpf_insn_local insns[] = {
		BPF_EMIT_CALL(BPF_FUNC_ktime_get_tai_ns),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	char log_buf[2048];
	memset(log_buf, 0, sizeof(log_buf));

	union bpf_attr_local attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = 1; /* BPF_PROG_TYPE_SOCKET_FILTER */
	attr.insn_cnt  = sizeof(insns) / sizeof(insns[0]);
	attr.insns     = (uint64_t)(uintptr_t)insns;
	attr.license   = (uint64_t)(uintptr_t)"GPL";
	attr.log_buf   = (uint64_t)(uintptr_t)log_buf;
	attr.log_size  = sizeof(log_buf);
	attr.log_level = 1;

	int fd = sys_bpf(BPF_CMD_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "BPF Subsystem");
	}

	if (fd >= 0) {
		report_pass(mod, "Load helper bpf_ktime_get_tai_ns (helper #208)");
		close(fd);
	} else if (errno == EPERM || errno == EACCES) {
		report_skip(mod, "Load helper bpf_ktime_get_tai_ns", "Unprivileged BPF disabled");
	} else {
		report_fail(mod, "Helper bpf_ktime_get_tai_ns", "errno=%d (%s) log: %s", errno, strerror(errno), log_buf);
	}
}

static void test_bpf_ringbuf(void)
{
	const char *mod = "BPF_RINGBUF";
	union bpf_attr_local attr;

	/* 1. Base Existence Check & non-power-of-2 max_entries check */
	memset(&attr, 0, sizeof(attr));
	attr.map_type    = BPF_MAP_TYPE_RINGBUF;
	attr.key_size    = 0;
	attr.value_size  = 0;
	attr.max_entries = 3000; /* Invalid: must be power of 2 and page-aligned */

	int fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "BPF Ringbuf map");
	}

	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects non-power-of-2 max_entries (-EINVAL)");
	} else if (fd >= 0) {
		close(fd);
		report_fail(mod, "Rejects non-power-of-2", "Created map with invalid size, fd=%d", fd);
		return;
	} else if (errno == EPERM) {
		report_skip(mod, "Rejects non-power-of-2", "CAP_BPF/CAP_SYS_ADMIN required");
		return;
	} else {
		report_fail(mod, "Rejects non-power-of-2", "errno=%d (%s)", errno, strerror(errno));
		return;
	}

	/* 2. Rejection of non-zero key_size */
	attr.key_size = 4;
	attr.max_entries = 4096;
	fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects non-zero key_size (-EINVAL)");
	} else {
		report_fail(mod, "Rejects non-zero key_size", "fd=%d errno=%d", fd, errno);
		if (fd >= 0) close(fd);
	}

	/* 3. Valid creation: 4096 bytes (1 page) */
	attr.key_size = 0;
	attr.value_size = 0;
	attr.max_entries = 4096;
	fd = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (fd < 0) {
		if (errno == EPERM) {
			report_skip(mod, "Create Ringbuf", "CAP_BPF/CAP_SYS_ADMIN required");
			return;
		}
		report_fail(mod, "Create Ringbuf", "Failed: %s (errno=%d)", strerror(errno), errno);
		return;
	}
	report_pass(mod, "Create BPF Ringbuf map (max_entries=4096)");

	/* 4. Memory-map verification:
	 * For BPF_MAP_TYPE_RINGBUF (kernel-to-user):
	 * Offset 0 (consumer page) is writable by userspace (PROT_READ | PROT_WRITE).
	 * Offset 4096 (producer page) is read-only (PROT_READ).
	 * Mapping offset 4096 with PROT_WRITE must fail with -EPERM.
	 */
	void *ptr_cons = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr_cons != MAP_FAILED) {
		report_pass(mod, "mmap consumer page (offset 0) with PROT_READ | PROT_WRITE");
		munmap(ptr_cons, 4096);
	} else {
		report_fail(mod, "mmap consumer page with PROT_READ | PROT_WRITE", "errno=%d (%s)", errno, strerror(errno));
	}

	void *ptr_ro = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 4096);
	if (ptr_ro != MAP_FAILED) {
		report_pass(mod, "mmap producer page (offset 4096) with PROT_READ");
		munmap(ptr_ro, 4096);
	} else {
		report_fail(mod, "mmap producer page with PROT_READ", "errno=%d (%s)", errno, strerror(errno));
	}

	void *ptr_wr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096);
	if (ptr_wr == MAP_FAILED && errno == EPERM) {
		report_pass(mod, "Rejects writable mmap of producer page at offset 4096 (-EPERM)");
	} else {
		report_fail(mod, "Rejects writable mmap of producer page", "ptr=%p errno=%d (%s)", ptr_wr, errno, strerror(errno));
		if (ptr_wr != MAP_FAILED) munmap(ptr_wr, 4096);
	}

	close(fd);
}

static void test_bpf_ktime_coarse_helper(void)
{
	const char *mod = "BPF_KTIME_COARSE";
	struct bpf_insn_local insns[] = {
		BPF_EMIT_CALL(BPF_FUNC_ktime_get_coarse_ns),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	char log_buf[2048];
	memset(log_buf, 0, sizeof(log_buf));

	union bpf_attr_local attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = 1; /* BPF_PROG_TYPE_SOCKET_FILTER */
	attr.insn_cnt  = sizeof(insns) / sizeof(insns[0]);
	attr.insns     = (uint64_t)(uintptr_t)insns;
	attr.license   = (uint64_t)(uintptr_t)"GPL";
	attr.log_buf   = (uint64_t)(uintptr_t)log_buf;
	attr.log_size  = sizeof(log_buf);
	attr.log_level = 1;

	int fd = sys_bpf(BPF_CMD_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "BPF Subsystem");
	}

	if (fd >= 0) {
		report_pass(mod, "Load helper bpf_ktime_get_coarse_ns (helper #160)");
		close(fd);
	} else if (errno == EPERM || errno == EACCES) {
		report_skip(mod, "Load helper bpf_ktime_get_coarse_ns", "Unprivileged BPF disabled");
	} else {
		report_fail(mod, "Helper bpf_ktime_get_coarse_ns", "errno=%d (%s) log: %s", errno, strerror(errno), log_buf);
	}
}

static void run_bpf_suite(void)
{
	/* Global BPF Subsystem base check */
	union bpf_attr_local attr;
	memset(&attr, 0, sizeof(attr));
	int ret = sys_bpf(BPF_CMD_MAP_CREATE, &attr, sizeof(attr));
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, "BPF", "BPF Subsystem");
	}

	test_bpf_bloom_filter();
	test_bpf_user_ringbuf();
	test_bpf_ringbuf();
	test_bpf_task_storage();
	test_bpf_syscall_prog();
	test_bpf_ktime_tai_helper();
	test_bpf_ktime_coarse_helper();
}

void register_suite_bpf(void)
{
	register_test_suite("bpf", "BPF Maps, Programs & Helpers (Bloom, User Ringbuf, Kernel Ringbuf, Task Storage, Syscall Prog, Coarse/TAI)", run_bpf_suite);
}
