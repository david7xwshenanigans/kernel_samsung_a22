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
		uint32_t *sq_tail = (uint32_t *)((uint8_t *)sq_ptr + params.sq_off.tail);
		uint32_t *sq_array = (uint32_t *)((uint8_t *)sq_ptr + params.sq_off.array);
		uint32_t index = *sq_tail & params.sq_off.ring_mask;

		memset(&sqes[index], 0, sizeof(struct io_uring_sqe_local));
		sqes[index].opcode = IORING_OP_NOP;
		sqes[index].user_data = 0xC0FFEEULL;
		sq_array[index] = index;
		(*sq_tail)++;

		ret = syscall(__NR_io_uring_enter, ring_fd, 1, 1, 0, NULL);
		if (ret >= 0) {
			report_pass(mod, "io_uring_enter submit 1 NOP SQE");

			/* 6. Reap CQE */
			uint32_t *cq_head = (uint32_t *)((uint8_t *)cq_ptr + params.cq_off.head);
			uint32_t *cq_tail = (uint32_t *)((uint8_t *)cq_ptr + params.cq_off.tail);
			struct io_uring_cqe_local *cqes = (struct io_uring_cqe_local *)((uint8_t *)cq_ptr + params.cq_off.cqes);

			if (*cq_head != *cq_tail) {
				struct io_uring_cqe_local *cqe = &cqes[*cq_head & params.cq_off.ring_mask];
				if (cqe->user_data == 0xC0FFEEULL && cqe->res == 0)
					report_pass(mod, "Reaped CQE with res=0 and matching user_data");
				else
					report_fail(mod, "Reap CQE", "Mismatch: user_data=0x%lx res=%d", (unsigned long)cqe->user_data, cqe->res);
				(*cq_head)++;
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

void register_suite_io_uring(void)
{
	register_test_suite("io_uring", "io_uring Subsystem (Setup, SQ/CQ Rings, NOP Execution, Eventfd, Probe, Buffers, Files)", test_io_uring);
}
