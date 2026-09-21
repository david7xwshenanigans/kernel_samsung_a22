#include "test_framework.h"
#include "test_uapi.h"
#include <fcntl.h>
#include <sys/mman.h>

#include <sys/wait.h>
#include <signal.h>

static void test_dmabuf_heaps(void)
{
	const char *mod = "DMA_BUF_HEAPS";
	const char *heap_path = "/dev/dma_heap/system";

	/* 1. Base Existence Check */
	if (access("/dev/dma_heap", F_OK) != 0 && errno == ENOENT) {
		CHECK_BASE_OR_SKIP(false, mod, "DMA-BUF Heaps subsystem /dev/dma_heap");
	}
	if (access(heap_path, F_OK) != 0 && errno == ENOENT) {
		CHECK_BASE_OR_SKIP(false, mod, "DMA-BUF Heap device /dev/dma_heap/system");
	}

	int heap_fd = open(heap_path, O_RDONLY | O_CLOEXEC);
	if (heap_fd < 0) {
		if (errno == ENOENT) {
			CHECK_BASE_OR_SKIP(false, mod, "DMA-BUF Heap device /dev/dma_heap/system");
		} else if (errno == EACCES || errno == EPERM) {
			report_skip(mod, "Open DMA-BUF Heap device", "Permission denied (%s). Root or media/graphics group required", strerror(errno));
			return;
		}
		report_fail(mod, "Open DMA-BUF Heap device", "Failed to open %s: %s", heap_path, strerror(errno));
		return;
	}
	report_pass(mod, "Open /dev/dma_heap/system descriptor");

	/* 2. Edge Case: len == 0 must fail with -EINVAL */
	struct dma_heap_allocation_data alloc_data;
	memset(&alloc_data, 0, sizeof(alloc_data));
	alloc_data.len = 0;
	alloc_data.fd_flags = O_CLOEXEC | O_RDWR;
	int ret = ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc_data);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects zero-length allocation (-EINVAL)");
	} else {
		report_fail(mod, "Rejects zero-length allocation", "ret=%d errno=%d (%s)", ret, errno, strerror(errno));
	}

	/* 3. Edge Case: non-zero fd field in input must fail with -EINVAL */
	memset(&alloc_data, 0, sizeof(alloc_data));
	alloc_data.len = 4096;
	alloc_data.fd = 99; /* Non-zero fd input must be rejected */
	alloc_data.fd_flags = O_CLOEXEC | O_RDWR;
	ret = ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc_data);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects non-zero initial fd (-EINVAL)");
	} else {
		report_fail(mod, "Rejects non-zero initial fd", "ret=%d errno=%d (%s)", ret, errno, strerror(errno));
		if (ret == 0 && (int)alloc_data.fd >= 0) close(alloc_data.fd);
	}

	/* 4. Edge Case: invalid fd_flags must fail with -EINVAL */
	memset(&alloc_data, 0, sizeof(alloc_data));
	alloc_data.len = 4096;
	alloc_data.fd_flags = 0xFFFFFFFFU;
	ret = ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc_data);
	if (ret < 0 && errno == EINVAL) {
		report_pass(mod, "Rejects invalid fd_flags (-EINVAL)");
	} else {
		report_fail(mod, "Rejects invalid fd_flags", "ret=%d errno=%d (%s)", ret, errno, strerror(errno));
		if (ret == 0 && (int)alloc_data.fd >= 0) close(alloc_data.fd);
	}

	/* 5. Edge Case: huge allocation exceeds available memory -> graceful failure.
	 * On host (x86_64), unpatched kernels lack the totalram_pages bounds check and
	 * will enter an intensive page reclaim loop causing system freeze. Skip on host.
	 * On ARM64 target, isolate in fork() child with 2-second alarm guard.
	 */
#ifndef __aarch64__
	report_skip(mod, "Rejects extreme allocation size", "Skipped on host architecture to prevent host OOM/freezing");
#else
	pid_t cpid = fork();
	if (cpid == 0) {
		alarm(2);
		memset(&alloc_data, 0, sizeof(alloc_data));
		alloc_data.len = 0x7FFFFFFFFFFFF000ULL;
		alloc_data.fd_flags = O_CLOEXEC | O_RDWR;
		ret = ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc_data);
		if (ret < 0 && (errno == ENOMEM || errno == EINVAL))
			_exit(0);
		if (ret == 0 && (int)alloc_data.fd >= 0)
			close(alloc_data.fd);
		_exit(1);
	} else if (cpid > 0) {
		int wstatus = 0;
		waitpid(cpid, &wstatus, 0);
		if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) {
			report_pass(mod, "Rejects extreme allocation size gracefully (-ENOMEM/-EINVAL)");
		} else if (WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGALRM) {
			report_fail(mod, "Rejects extreme allocation size", "Timed out after 2s (kernel hung allocating pages)");
		} else {
			report_fail(mod, "Rejects extreme allocation size", "Child exited with status 0x%x", wstatus);
		}
	} else {
		report_fail(mod, "Fork test worker", "errno=%d", errno);
	}
#endif

	/* 6. Happy Path: allocate 1 page, mmap, write, sync, verify */
	memset(&alloc_data, 0, sizeof(alloc_data));
	alloc_data.len = 4096;
	alloc_data.fd_flags = O_CLOEXEC | O_RDWR;
	ret = ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc_data);
	if (ret == 0 && (int)alloc_data.fd >= 0) {
		report_pass(mod, "Allocate 4096-byte DMA-BUF buffer");
		int dma_buf_fd = alloc_data.fd;

		void *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf_fd, 0);
		if (buf != MAP_FAILED) {
			struct dma_buf_sync sync = { .flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_WRITE };
			ioctl(dma_buf_fd, DMA_BUF_IOCTL_SYNC, &sync);

			memset(buf, 0xA5, 4096);

			sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE;
			ioctl(dma_buf_fd, DMA_BUF_IOCTL_SYNC, &sync);

			sync.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ;
			ioctl(dma_buf_fd, DMA_BUF_IOCTL_SYNC, &sync);

			uint8_t *byte_buf = (uint8_t *)buf;
			if (byte_buf[0] == 0xA5 && byte_buf[4095] == 0xA5)
				report_pass(mod, "DMA-BUF mmap memory read/write integrity verified");
			else
				report_fail(mod, "DMA-BUF memory integrity", "Buffer byte verification failed");

			sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ;
			ioctl(dma_buf_fd, DMA_BUF_IOCTL_SYNC, &sync);

			munmap(buf, 4096);
		} else {
			report_fail(mod, "mmap DMA-BUF fd", "errno=%d (%s)", errno, strerror(errno));
		}

		/* 7. Edge Case: non-zero offset mmap must fail with -EINVAL */
		void *bad_buf = mmap(NULL, 4096, PROT_READ, MAP_SHARED, dma_buf_fd, 4096);
		if (bad_buf == MAP_FAILED && errno == EINVAL) {
			report_pass(mod, "DMA-BUF rejects non-zero offset mmap (-EINVAL)");
		} else {
			report_fail(mod, "DMA-BUF non-zero offset mmap", "ptr=%p errno=%d", bad_buf, errno);
			if (bad_buf != MAP_FAILED) munmap(bad_buf, 4096);
		}

		/* 8. Edge Case: invalid sync flags rejection (-EINVAL) */
		struct dma_buf_sync bad_sync = { .flags = 0xDEAD0000U };
		ret = ioctl(dma_buf_fd, DMA_BUF_IOCTL_SYNC, &bad_sync);
		if (ret < 0 && errno == EINVAL) {
			report_pass(mod, "DMA-BUF rejects invalid sync flags (-EINVAL)");
		} else {
			report_fail(mod, "DMA-BUF invalid sync flags", "ret=%d errno=%d", ret, errno);
		}

		/* 9. dup() refcount persistence */
		int dup_fd = dup(dma_buf_fd);
		if (dup_fd >= 0) {
			close(dma_buf_fd);
			struct dma_buf_sync dup_sync = { .flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ };
			ret = ioctl(dup_fd, DMA_BUF_IOCTL_SYNC, &dup_sync);
			if (ret == 0) {
				report_pass(mod, "DMA-BUF dup() preserves valid handle across close()");
				dup_sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ;
				ioctl(dup_fd, DMA_BUF_IOCTL_SYNC, &dup_sync);
			} else {
				report_fail(mod, "DMA-BUF dup sync", "ret=%d errno=%d", ret, errno);
			}
			close(dup_fd);
		} else {
			close(dma_buf_fd);
			report_fail(mod, "DMA-BUF dup", "errno=%d", errno);
		}
	} else {
		report_fail(mod, "Allocate 4096-byte DMA-BUF buffer", "ioctl failed: %s (errno=%d)", strerror(errno), errno);
	}

	close(heap_fd);
}

void register_suite_dmabuf_heaps(void)
{
	register_test_suite("dmabuf", "DMA-BUF Heaps Subsystem (/dev/dma_heap/system)", test_dmabuf_heaps);
}
