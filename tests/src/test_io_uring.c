#include "test_framework.h"
#include "test_uapi.h"
#include <sys/mman.h>
#include <sys/eventfd.h>

static void test_io_uring(void)
{
	const char *mod = "IO_URING";
	struct io_uring_params_local params;

	/* 1. Base Existence Check & entries == 0 rejection */
	memset(&params, 0, sizeof(params));
	long ret = syscall(__NR_io_uring_setup, 0, &params);
	if (ret < 0 && errno == ENOSYS) {
		CHECK_BASE_OR_SKIP(false, mod, "io_uring subsystem");
	}

	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "io_uring_setup rejects entries=0 (-EINVAL)");
	} else if (ret >= 0) {
		close(ret);
		report_fail(mod, "Rejects entries=0", "Unexpectedly created ring fd=%ld", ret);
		return;
	} else {
		report_fail(mod, "Rejects entries=0", "errno=%d (%s)", errno, strerror(errno));
		return;
	}

	/* 2. Edge Case: invalid flags must fail with -EINVAL */
	memset(&params, 0, sizeof(params));
	params.flags = 0xFFFFFFFFU;
	ret = syscall(__NR_io_uring_setup, 4, &params);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "io_uring_setup rejects invalid flags (-EINVAL)");
	} else {
		report_fail(mod, "Rejects invalid flags", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		if (ret >= 0) close(ret);
	}

	/* 3. Valid setup */
	memset(&params, 0, sizeof(params));
	int ring_fd = syscall(__NR_io_uring_setup, 4, &params);
	if (ring_fd < 0) {
		report_fail(mod, "io_uring_setup", "Failed with errno=%d (%s)", errno, strerror(errno));
		return;
	}
	report_pass(mod, "io_uring_setup creates ring fd");
	report_info("sq_entries=%u cq_entries=%u features=0x%x",
		    params.sq_entries, params.cq_entries, params.features);

	/* 4. Memory-map rings */
	uint32_t sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(uint32_t);
	uint32_t cq_ring_sz = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe_local);

	void *sq_ptr = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
	void *cq_ptr = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_CQ_RING);
	void *sqes_ptr = mmap(NULL, params.sq_entries * sizeof(struct io_uring_sqe_local),
			      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);

	if (sq_ptr != MAP_FAILED && cq_ptr != MAP_FAILED && sqes_ptr != MAP_FAILED) {
		report_pass(mod, "mmap SQ ring, CQ ring, and SQE array buffers");

		/* 5. Submit NOP SQE */
		struct io_uring_sqe_local *sqes = (struct io_uring_sqe_local *)sqes_ptr;
		volatile uint32_t *sq_tail = (volatile uint32_t *)((uint8_t *)sq_ptr + params.sq_off.tail);
		volatile uint32_t *sq_array = (volatile uint32_t *)((uint8_t *)sq_ptr + params.sq_off.array);
		uint32_t sq_mask = *(uint32_t *)((uint8_t *)sq_ptr + params.sq_off.ring_mask);
		uint32_t cq_mask = *(uint32_t *)((uint8_t *)cq_ptr + params.cq_off.ring_mask);
		uint32_t index = *sq_tail & sq_mask;

		memset(&sqes[index], 0, sizeof(struct io_uring_sqe_local));
		sqes[index].opcode = IORING_OP_NOP;
		sqes[index].user_data = 0xC0FFEEULL;
		sq_array[index] = index;
		__atomic_store_n(sq_tail, *sq_tail + 1, __ATOMIC_RELEASE);

		ret = syscall(__NR_io_uring_enter, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL);
		if (ret >= 0) {
			report_pass(mod, "io_uring_enter submit 1 NOP SQE");

			/* 6. Reap CQE */
			volatile uint32_t *cq_head = (volatile uint32_t *)((uint8_t *)cq_ptr + params.cq_off.head);
			volatile uint32_t *cq_tail = (volatile uint32_t *)((uint8_t *)cq_ptr + params.cq_off.tail);
			struct io_uring_cqe_local *cqes = (struct io_uring_cqe_local *)((uint8_t *)cq_ptr + params.cq_off.cqes);

			if (*cq_head != *cq_tail) {
				struct io_uring_cqe_local *cqe = &cqes[*cq_head & cq_mask];
				if (cqe->user_data == 0xC0FFEEULL && cqe->res == 0)
					report_pass(mod, "Reaped CQE with res=0 and matching user_data");
				else
					report_fail(mod, "Reap CQE", "Mismatch: user_data=0x%lx res=%d", (unsigned long)cqe->user_data, cqe->res);
				__atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
			} else {
				report_fail(mod, "Reap CQE", "No CQE produced after enter");
			}
		} else {
			report_fail(mod, "io_uring_enter", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		}

		munmap(sq_ptr, sq_ring_sz);
		munmap(cq_ptr, cq_ring_sz);
		munmap(sqes_ptr, params.sq_entries * sizeof(struct io_uring_sqe_local));
	} else {
		report_fail(mod, "mmap rings", "Failed: sq=%p cq=%p sqes=%p", sq_ptr, cq_ptr, sqes_ptr);
		if (sq_ptr != MAP_FAILED) munmap(sq_ptr, sq_ring_sz);
		if (cq_ptr != MAP_FAILED) munmap(cq_ptr, cq_ring_sz);
		if (sqes_ptr != MAP_FAILED) munmap(sqes_ptr, params.sq_entries * sizeof(struct io_uring_sqe_local));
	}

	/* 7. Eventfd registration */
	int efd = eventfd(0, EFD_CLOEXEC);
	if (efd >= 0) {
		ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_EVENTFD, &efd, 1);
		if (ret == 0) {
			report_pass(mod, "io_uring_register (IORING_REGISTER_EVENTFD)");
			syscall(__NR_io_uring_register, ring_fd, IORING_UNREGISTER_EVENTFD, NULL, 0);
		} else {
			report_fail(mod, "io_uring_register eventfd", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		}
		close(efd);
	}

	/* 8. Probe registration (query supported opcodes) */
	struct io_uring_probe_local probe;
	memset(&probe, 0, sizeof(probe));
	ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_PROBE, &probe, 256);
	if (ret == 0) {
		report_pass(mod, "io_uring_register (IORING_REGISTER_PROBE)");
		report_info("io_uring probe: last_op=%u ops_len=%u", probe.last_op, probe.ops_len);
	} else {
		report_fail(mod, "io_uring_register probe", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
	}

	/* 9. Fixed Buffer registration and unregistration */
	char reg_buf[4096];
	struct iovec iov = {
		.iov_base = reg_buf,
		.iov_len  = sizeof(reg_buf),
	};
	ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_BUFFERS, &iov, 1);
	if (ret == 0) {
		report_pass(mod, "io_uring_register (IORING_REGISTER_BUFFERS)");
		ret = syscall(__NR_io_uring_register, ring_fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
		if (ret == 0)
			report_pass(mod, "io_uring_register (IORING_UNREGISTER_BUFFERS)");
		else
			report_fail(mod, "io_uring unregister buffers", "ret=%ld errno=%d", ret, errno);
	} else {
		report_fail(mod, "io_uring register buffers", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
	}

	/* 10. Fixed File table registration and unregistration */
	int dummy_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (dummy_fd >= 0) {
		int file_fds[2] = { dummy_fd, dummy_fd };
		ret = syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_FILES, file_fds, 2);
		if (ret == 0) {
			report_pass(mod, "io_uring_register (IORING_REGISTER_FILES)");
			ret = syscall(__NR_io_uring_register, ring_fd, IORING_UNREGISTER_FILES, NULL, 0);
			if (ret == 0)
				report_pass(mod, "io_uring_register (IORING_UNREGISTER_FILES)");
			else
				report_fail(mod, "io_uring unregister files", "ret=%ld errno=%d", ret, errno);
		} else {
			report_fail(mod, "io_uring register files", "ret=%ld errno=%d (%s)", ret, errno, strerror(errno));
		}
		close(dummy_fd);
	}

	close(ring_fd);
}

static void test_io_uring_read_write(void)
{
	const char *mod = "IO_URING_RW";
	struct io_uring_params_local params;
	memset(&params, 0, sizeof(params));

	int ring_fd = syscall(__NR_io_uring_setup, 8, &params);
	if (ring_fd < 0) {
		CHECK_BASE_OR_SKIP(false, mod, "io_uring_setup for RW test");
	}

	uint32_t sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(uint32_t);
	uint32_t cq_ring_sz = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe_local);
	uint32_t sqes_sz = params.sq_entries * sizeof(struct io_uring_sqe_local);

	void *sq_ptr = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
	void *cq_ptr = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_CQ_RING);
	void *sqes_ptr = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);

	if (sq_ptr == MAP_FAILED || cq_ptr == MAP_FAILED || sqes_ptr == MAP_FAILED) {
		report_fail(mod, "mmap ring buffers", "errno=%d", errno);
		if (sq_ptr != MAP_FAILED) munmap(sq_ptr, sq_ring_sz);
		if (cq_ptr != MAP_FAILED) munmap(cq_ptr, cq_ring_sz);
		if (sqes_ptr != MAP_FAILED) munmap(sqes_ptr, sqes_sz);
		close(ring_fd);
		return;
	}

	int pfd[2];
	if (pipe(pfd) < 0) {
		report_fail(mod, "Create test pipe", "errno=%d", errno);
		goto cleanup_mmap;
	}

	struct io_uring_sqe_local *sqes = (struct io_uring_sqe_local *)sqes_ptr;
	volatile uint32_t *sq_tail = (volatile uint32_t *)((uint8_t *)sq_ptr + params.sq_off.tail);
	volatile uint32_t *sq_array = (volatile uint32_t *)((uint8_t *)sq_ptr + params.sq_off.array);
	volatile uint32_t *cq_head = (volatile uint32_t *)((uint8_t *)cq_ptr + params.cq_off.head);
	volatile uint32_t *cq_tail = (volatile uint32_t *)((uint8_t *)cq_ptr + params.cq_off.tail);
	uint32_t sq_mask = *(uint32_t *)((uint8_t *)sq_ptr + params.sq_off.ring_mask);
	uint32_t cq_mask = *(uint32_t *)((uint8_t *)cq_ptr + params.cq_off.ring_mask);
	struct io_uring_cqe_local *cqes = (struct io_uring_cqe_local *)((uint8_t *)cq_ptr + params.cq_off.cqes);

	/* 1. Test IORING_OP_WRITEV on pipe write end */
	const char *msg = "IO_URING_ASYNC_PIPELINE_VALIDATION_STRING_12345678";
	size_t msg_len = strlen(msg);
	struct iovec write_iov = {
		.iov_base = (void *)msg,
		.iov_len  = msg_len,
	};

	uint32_t idx = *sq_tail & sq_mask;
	memset(&sqes[idx], 0, sizeof(struct io_uring_sqe_local));
	sqes[idx].opcode = IORING_OP_WRITEV;
	sqes[idx].fd = pfd[1];
	sqes[idx].addr = (uint64_t)&write_iov;
	sqes[idx].len = 1;
	sqes[idx].user_data = 0x111ULL;
	sq_array[idx] = idx;
	__atomic_store_n(sq_tail, *sq_tail + 1, __ATOMIC_RELEASE);

	long ret = syscall(__NR_io_uring_enter, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL);
	if (ret >= 0 && *cq_head != *cq_tail) {
		struct io_uring_cqe_local *cqe = &cqes[*cq_head & cq_mask];
		if (cqe->user_data == 0x111ULL && cqe->res == (int32_t)msg_len) {
			report_pass(mod, "IORING_OP_WRITEV pipe write execution");
		} else {
			report_fail(mod, "IORING_OP_WRITEV", "res=%d expected=%zu", cqe->res, msg_len);
		}
		__atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
	} else {
		report_fail(mod, "IORING_OP_WRITEV submit", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. Test IORING_OP_READV on pipe read end */
	char read_buf[128];
	memset(read_buf, 0, sizeof(read_buf));
	struct iovec read_iov = {
		.iov_base = read_buf,
		.iov_len  = sizeof(read_buf),
	};

	idx = *sq_tail & sq_mask;
	memset(&sqes[idx], 0, sizeof(struct io_uring_sqe_local));
	sqes[idx].opcode = IORING_OP_READV;
	sqes[idx].fd = pfd[0];
	sqes[idx].addr = (uint64_t)&read_iov;
	sqes[idx].len = 1;
	sqes[idx].user_data = 0x222ULL;
	sq_array[idx] = idx;
	__atomic_store_n(sq_tail, *sq_tail + 1, __ATOMIC_RELEASE);

	ret = syscall(__NR_io_uring_enter, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL);
	if (ret >= 0 && *cq_head != *cq_tail) {
		struct io_uring_cqe_local *cqe = &cqes[*cq_head & cq_mask];
		if (cqe->user_data == 0x222ULL && cqe->res == (int32_t)msg_len &&
		    memcmp(read_buf, msg, msg_len) == 0) {
			report_pass(mod, "IORING_OP_READV pipe read & data verification");
		} else {
			report_fail(mod, "IORING_OP_READV", "user_data=0x%lx res=%d content match=%d",
				    (unsigned long)cqe->user_data, cqe->res, memcmp(read_buf, msg, msg_len) == 0);
		}
		__atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
	} else {
		report_fail(mod, "IORING_OP_READV submit", "ret=%ld errno=%d", ret, errno);
	}

	close(pfd[0]);
	close(pfd[1]);

cleanup_mmap:
	munmap(sq_ptr, sq_ring_sz);
	munmap(cq_ptr, cq_ring_sz);
	munmap(sqes_ptr, sqes_sz);
	close(ring_fd);
}

static void test_io_uring_timeout_and_cancel(void)
{
	const char *mod = "IO_URING_TIMEOUT";
	struct io_uring_params_local params;
	memset(&params, 0, sizeof(params));

	int ring_fd = syscall(__NR_io_uring_setup, 8, &params);
	if (ring_fd < 0) {
		CHECK_BASE_OR_SKIP(false, mod, "io_uring_setup for Timeout test");
	}

	uint32_t sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(uint32_t);
	uint32_t cq_ring_sz = params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe_local);
	uint32_t sqes_sz = params.sq_entries * sizeof(struct io_uring_sqe_local);

	void *sq_ptr = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
	void *cq_ptr = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_CQ_RING);
	void *sqes_ptr = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);

	if (sq_ptr == MAP_FAILED || cq_ptr == MAP_FAILED || sqes_ptr == MAP_FAILED) {
		report_fail(mod, "mmap ring buffers", "errno=%d", errno);
		if (sq_ptr != MAP_FAILED) munmap(sq_ptr, sq_ring_sz);
		if (cq_ptr != MAP_FAILED) munmap(cq_ptr, cq_ring_sz);
		if (sqes_ptr != MAP_FAILED) munmap(sqes_ptr, sqes_sz);
		close(ring_fd);
		return;
	}

	struct io_uring_sqe_local *sqes = (struct io_uring_sqe_local *)sqes_ptr;
	volatile uint32_t *sq_tail = (volatile uint32_t *)((uint8_t *)sq_ptr + params.sq_off.tail);
	volatile uint32_t *sq_array = (volatile uint32_t *)((uint8_t *)sq_ptr + params.sq_off.array);
	volatile uint32_t *cq_head = (volatile uint32_t *)((uint8_t *)cq_ptr + params.cq_off.head);
	volatile uint32_t *cq_tail = (volatile uint32_t *)((uint8_t *)cq_ptr + params.cq_off.tail);
	uint32_t sq_mask = *(uint32_t *)((uint8_t *)sq_ptr + params.sq_off.ring_mask);
	uint32_t cq_mask = *(uint32_t *)((uint8_t *)cq_ptr + params.cq_off.ring_mask);
	struct io_uring_cqe_local *cqes = (struct io_uring_cqe_local *)((uint8_t *)cq_ptr + params.cq_off.cqes);

	/* 1. Test IORING_OP_TIMEOUT expiring after 10ms -> returns -ETIME */
	struct __kernel_timespec_local ts = {
		.tv_sec = 0,
		.tv_nsec = 10000000, /* 10 ms */
	};

	uint32_t idx = *sq_tail & sq_mask;
	memset(&sqes[idx], 0, sizeof(struct io_uring_sqe_local));
	sqes[idx].opcode = IORING_OP_TIMEOUT;
	sqes[idx].addr = (uint64_t)&ts;
	sqes[idx].len = 1;
	sqes[idx].user_data = 0xAA1ULL;
	sq_array[idx] = idx;
	__atomic_store_n(sq_tail, *sq_tail + 1, __ATOMIC_RELEASE);

	long ret = syscall(__NR_io_uring_enter, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL);
	if (ret >= 0 && *cq_head != *cq_tail) {
		struct io_uring_cqe_local *cqe = &cqes[*cq_head & cq_mask];
		if (cqe->user_data == 0xAA1ULL && cqe->res == -ETIME) {
			report_pass(mod, "IORING_OP_TIMEOUT expired returning -ETIME");
		} else {
			report_fail(mod, "IORING_OP_TIMEOUT", "user_data=0x%lx res=%d", (unsigned long)cqe->user_data, cqe->res);
		}
		__atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
	} else {
		report_fail(mod, "IORING_OP_TIMEOUT enter", "ret=%ld errno=%d", ret, errno);
	}

	/* 2. Test IORING_OP_TIMEOUT_REMOVE removing an in-flight 5s timeout */
	struct __kernel_timespec_local long_ts = {
		.tv_sec = 5,
		.tv_nsec = 0,
	};

	idx = *sq_tail & sq_mask;
	memset(&sqes[idx], 0, sizeof(struct io_uring_sqe_local));
	sqes[idx].opcode = IORING_OP_TIMEOUT;
	sqes[idx].addr = (uint64_t)&long_ts;
	sqes[idx].len = 1;
	sqes[idx].user_data = 0xBB2ULL;
	sq_array[idx] = idx;
	__atomic_store_n(sq_tail, *sq_tail + 1, __ATOMIC_RELEASE);

	/* Submit timeout_remove SQE immediately targeting 0xBB2ULL */
	uint32_t c_idx = *sq_tail & sq_mask;
	memset(&sqes[c_idx], 0, sizeof(struct io_uring_sqe_local));
	sqes[c_idx].opcode = IORING_OP_TIMEOUT_REMOVE;
	sqes[c_idx].addr = 0xBB2ULL; /* Target user_data */
	sqes[c_idx].user_data = 0xCC3ULL;
	sq_array[c_idx] = c_idx;
	__atomic_store_n(sq_tail, *sq_tail + 1, __ATOMIC_RELEASE);

	ret = syscall(__NR_io_uring_enter, ring_fd, 2, 2, IORING_ENTER_GETEVENTS, NULL);
	if (ret >= 0) {
		int canceled_count = 0, success_cancel_sqe = 0;
		while (*cq_head != *cq_tail) {
			struct io_uring_cqe_local *cqe = &cqes[*cq_head & cq_mask];
			if (cqe->user_data == 0xCC3ULL && cqe->res == 0)
				success_cancel_sqe++;
			if (cqe->user_data == 0xBB2ULL && cqe->res == -ECANCELED)
				canceled_count++;
			__atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
		}
		if (success_cancel_sqe == 1 && canceled_count == 1) {
			report_pass(mod, "IORING_OP_TIMEOUT_REMOVE removed in-flight timeout (-ECANCELED)");
		} else {
			report_fail(mod, "IORING_OP_TIMEOUT_REMOVE", "remove_res=%d timeout_res=%d", success_cancel_sqe, canceled_count);
		}
	} else {
		report_fail(mod, "IORING_OP_TIMEOUT_REMOVE enter", "ret=%ld errno=%d", ret, errno);
	}

	/* 3. Test invalid opcode rejection: opcode 0xFD must return -EINVAL/-EOPNOTSUPP in CQE */
	idx = *sq_tail & sq_mask;
	memset(&sqes[idx], 0, sizeof(struct io_uring_sqe_local));
	sqes[idx].opcode = 0xFD;
	sqes[idx].user_data = 0xDEADULL;
	sq_array[idx] = idx;
	__atomic_store_n(sq_tail, *sq_tail + 1, __ATOMIC_RELEASE);

	ret = syscall(__NR_io_uring_enter, ring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL);
	if (ret >= 0 && *cq_head != *cq_tail) {
		struct io_uring_cqe_local *cqe = &cqes[*cq_head & cq_mask];
		if (cqe->user_data == 0xDEADULL && (cqe->res == -EINVAL || cqe->res == -EOPNOTSUPP)) {
			report_pass(mod, "Invalid SQE opcode gracefully rejected in CQE (-EINVAL/-EOPNOTSUPP)");
		} else {
			report_fail(mod, "Invalid SQE opcode", "Unexpected CQE res=%d", cqe->res);
		}
		__atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
	} else {
		report_fail(mod, "Invalid SQE enter", "ret=%ld errno=%d", ret, errno);
	}

	munmap(sq_ptr, sq_ring_sz);
	munmap(cq_ptr, cq_ring_sz);
	munmap(sqes_ptr, sqes_sz);
	close(ring_fd);
}

static void run_io_uring_suite(void)
{
	test_io_uring();
	test_io_uring_read_write();
	test_io_uring_timeout_and_cancel();
}

void register_suite_io_uring(void)
{
	register_test_suite("io_uring", "io_uring Subsystem (Setup, SQ/CQ Rings, Read/Write, Timeouts, Cancel, Probe, Buffers, Files)", run_io_uring_suite);
}

