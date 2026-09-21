#ifndef TEST_UAPI_H
#define TEST_UAPI_H

#include <stdint.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

/* ========================================================================= */
/* Syscall Numbers (arm64 modern backports)                                  */
/* ========================================================================= */

#ifndef __NR_rseq
#define __NR_rseq 293
#endif

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif

#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif

#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif

#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif

#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif

#ifndef __NR_fspick
#define __NR_fspick 433
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#ifndef __NR_close_range
#define __NR_close_range 436
#endif

#ifndef __NR_openat2
#define __NR_openat2 437
#endif

#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif

#ifndef __NR_epoll_pwait2
#define __NR_epoll_pwait2 441
#endif

#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif

#ifndef __NR_quotactl_fd
#define __NR_quotactl_fd 443
#endif

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif

#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif

#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef __NR_memfd_secret
#define __NR_memfd_secret 447
#endif

#ifndef __NR_process_mrelease
#define __NR_process_mrelease 448
#endif

#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif

#ifndef __NR_set_mempolicy_home_node
#define __NR_set_mempolicy_home_node 450
#endif

/* ========================================================================= */
/* BPF Subsystem UAPI Definitions                                            */
/* ========================================================================= */

#define BPF_CMD_MAP_CREATE        0
#define BPF_CMD_MAP_LOOKUP_ELEM   1
#define BPF_CMD_MAP_UPDATE_ELEM   2
#define BPF_CMD_MAP_DELETE_ELEM   3
#define BPF_CMD_PROG_LOAD         5

#define BPF_MAP_TYPE_HASH         1
#define BPF_MAP_TYPE_ARRAY        2
#define BPF_MAP_TYPE_RINGBUF      27
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_MAP_TYPE_BLOOM_FILTER 30
#define BPF_MAP_TYPE_USER_RINGBUF 31
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define BPF_PROG_TYPE_SYSCALL     31

#define BPF_ANY                   0
#define BPF_NOEXIST               1
#define BPF_EXIST                 2

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF             50
#endif
#ifndef SO_DETACH_BPF
#define SO_DETACH_BPF             27
#endif

#define BPF_F_NO_PREALLOC         (1U << 0)
#define BPF_FUNC_ktime_get_coarse_ns 160
#define BPF_FUNC_check_mtu           163
#define BPF_FUNC_for_each_map_elem   164
#define BPF_FUNC_snprintf            165
#define BPF_FUNC_strncmp             182
#define BPF_FUNC_copy_from_user_task 191
#define BPF_FUNC_map_lookup_percpu_elem 195
#define BPF_FUNC_ktime_get_tai_ns    208

union bpf_attr_local {
	struct {
		uint32_t map_type;
		uint32_t key_size;
		uint32_t value_size;
		uint32_t max_entries;
		uint32_t map_flags;
		uint32_t inner_map_fd;
		uint32_t numa_node;
		char     map_name[16];
		uint32_t map_ifindex;
		uint32_t btf_fd;
		uint32_t btf_key_type_id;
		uint32_t btf_value_type_id;
		uint32_t btf_vmlinux_value_type_id;
		uint64_t map_extra;
	};
	struct {
		uint32_t map_fd;
		uint64_t key;
		union {
			uint64_t value;
			uint64_t next_key;
		};
		uint64_t flags;
	};
	struct {
		uint32_t prog_type;
		uint32_t insn_cnt;
		uint64_t insns;
		uint64_t license;
		uint32_t log_level;
		uint32_t log_size;
		uint64_t log_buf;
		uint32_t kern_version;
		uint32_t prog_flags;
		char     prog_name[16];
		uint32_t prog_ifindex;
		uint32_t expected_attach_type;
	};
};

struct bpf_insn_local {
	uint8_t  code;
	uint8_t  dst_reg:4;
	uint8_t  src_reg:4;
	int16_t  off;
	int32_t  imm;
};

#define BPF_ALU64  0x07
#define BPF_MOV    0xb0
#define BPF_K      0x00
#define BPF_JMP    0x05
#define BPF_CALL   0x80
#define BPF_EXIT   0x90
#define BPF_REG_0  0
#define BPF_REG_1  1

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
	((struct bpf_insn_local){ .code = (CODE), .dst_reg = (DST), .src_reg = (SRC), .off = (OFF), .imm = (IMM) })

#define BPF_MOV64_IMM(DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define BPF_EMIT_CALL(FUNC)     BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, FUNC)
#define BPF_EXIT_INSN()         BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

static inline int sys_bpf(int cmd, union bpf_attr_local *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

/* ========================================================================= */
/* DMA-BUF Heaps UAPI Definitions                                            */
/* ========================================================================= */

struct dma_heap_allocation_data {
	uint64_t len;
	uint32_t fd;
	uint32_t fd_flags;
	uint64_t heap_flags;
};

#define DMA_HEAP_IOC_MAGIC   'H'
#define DMA_HEAP_IOCTL_ALLOC _IOWR(DMA_HEAP_IOC_MAGIC, 0x0, struct dma_heap_allocation_data)

struct dma_buf_sync {
	uint64_t flags;
};

#define DMA_BUF_SYNC_READ      (1 << 0)
#define DMA_BUF_SYNC_WRITE     (2 << 0)
#define DMA_BUF_SYNC_RW        (DMA_BUF_SYNC_READ | DMA_BUF_SYNC_WRITE)
#define DMA_BUF_SYNC_START     (0 << 2)
#define DMA_BUF_SYNC_END       (1 << 2)
#define DMA_BUF_BASE           'b'
#define DMA_BUF_IOCTL_SYNC     _IOW(DMA_BUF_BASE, 0, struct dma_buf_sync)

/* ========================================================================= */
/* io_uring Subsystem UAPI Definitions                                       */
/* ========================================================================= */

struct io_sqring_offsets {
	uint32_t head;
	uint32_t tail;
	uint32_t ring_mask;
	uint32_t ring_entries;
	uint32_t flags;
	uint32_t dropped;
	uint32_t array;
	uint32_t resv1;
	uint64_t resv2;
};

struct io_cqring_offsets {
	uint32_t head;
	uint32_t tail;
	uint32_t ring_mask;
	uint32_t ring_entries;
	uint32_t overflow;
	uint32_t cqes;
	uint32_t flags;
	uint32_t resv1;
	uint64_t resv2;
};

struct io_uring_params_local {
	uint32_t sq_entries;
	uint32_t cq_entries;
	uint32_t flags;
	uint32_t sq_thread_cpu;
	uint32_t sq_thread_idle;
	uint32_t features;
	uint32_t wq_fd;
	uint32_t resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

struct io_uring_sqe_local {
	uint8_t  opcode;
	uint8_t  flags;
	uint16_t ioprio;
	int32_t  fd;
	union {
		uint64_t off;
		uint64_t addr2;
	};
	union {
		uint64_t addr;
		uint64_t splice_off_in;
	};
	uint32_t len;
	union {
		uint32_t rw_flags;
		uint32_t fsync_flags;
		uint32_t poll_events;
		uint32_t poll32_events;
		uint32_t sync_range_flags;
		uint32_t msg_flags;
		uint32_t timeout_flags;
		uint32_t accept_flags;
		uint32_t cancel_flags;
		uint32_t open_flags;
		uint32_t statx_flags;
		uint32_t fadvise_advice;
		uint32_t splice_flags;
		uint32_t rename_flags;
		uint32_t unlink_flags;
		uint32_t hardlink_flags;
	};
	uint64_t user_data;
	union {
		uint16_t buf_index;
		uint16_t buf_group;
	} __attribute__((packed));
	uint16_t personality;
	union {
		int32_t  splice_fd_in;
		uint32_t file_index;
	};
	uint64_t pad2[2];
};

struct io_uring_cqe_local {
	uint64_t user_data;
	int32_t  res;
	uint32_t flags;
};

#define IORING_OFF_SQ_RING     0ULL
#define IORING_OFF_CQ_RING     0x8000000ULL
#define IORING_OFF_SQES        0x10000000ULL

#define IORING_OP_NOP          0
#define IORING_OP_READV        1
#define IORING_OP_WRITEV       2
#define IORING_OP_FSYNC        3
#define IORING_OP_POLL_ADD     6
#define IORING_OP_POLL_REMOVE  7
#define IORING_OP_TIMEOUT      11
#define IORING_OP_TIMEOUT_REMOVE 12
#define IORING_OP_ASYNC_CANCEL 14
#define IORING_OP_READ         22
#define IORING_OP_WRITE        23

#define IORING_ENTER_GETEVENTS (1U << 0)

struct __kernel_timespec_local {
	int64_t   tv_sec;
	long long tv_nsec;
};

#define IORING_REGISTER_BUFFERS      0
#define IORING_UNREGISTER_BUFFERS    1
#define IORING_REGISTER_FILES        2
#define IORING_UNREGISTER_FILES      3
#define IORING_REGISTER_EVENTFD      4
#define IORING_UNREGISTER_EVENTFD    5
#define IORING_REGISTER_PROBE        8

struct io_uring_probe_op_local {
	uint8_t  op;
	uint8_t  resv;
	uint16_t flags;
	uint32_t resv2;
};

struct io_uring_probe_local {
	uint8_t  last_op;
	uint8_t  ops_len;
	uint16_t resv;
	uint32_t resv2[3];
	struct io_uring_probe_op_local ops[256];
};

/* ========================================================================= */
/* Syscall-specific UAPI Structs & Flags                                     */
/* ========================================================================= */

/* clone3 */
struct clone_args_local {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
	uint64_t set_tid;
	uint64_t set_tid_size;
	uint64_t cgroup;
};

/* openat2 */
struct open_how_local {
	uint64_t flags;
	uint64_t mode;
	uint64_t resolve;
};

#define RESOLVE_NO_XDEV        0x01ULL
#define RESOLVE_NO_MAGICLINKS  0x02ULL
#define RESOLVE_NO_SYMLINKS    0x04ULL
#define RESOLVE_BENEATH        0x08ULL
#define RESOLVE_IN_ROOT        0x10ULL
#define RESOLVE_CACHED         0x20ULL

/* close_range */
#define CLOSE_RANGE_UNSHARE (1U << 1)
#define CLOSE_RANGE_CLOEXEC (1U << 2)

/* process_madvise */
#define MADV_COLD 20
#define MADV_PAGEOUT 21

/* rseq */
struct rseq_local {
	uint32_t cpu_id_start;
	uint32_t cpu_id;
	uint64_t rseq_cs;
	uint32_t flags;
} __attribute__((aligned(4 * sizeof(uint64_t))));

#define RSEQ_FLAG_UNREGISTER (1U << 0)
#define RSEQ_SIG 0x53053053

/* Landlock */
struct landlock_ruleset_attr_local {
	uint64_t handled_access_fs;
};

struct landlock_path_beneath_attr_local {
	uint64_t allowed_access;
	int32_t  parent_fd;
} __attribute__((packed));

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_ACCESS_FS_EXECUTE      (1ULL << 0)

/* futex_waitv */
#ifndef FUTEX_32
#define FUTEX_32 2
#endif

#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif

#ifndef FUTEX_WAITV_MAX
#define FUTEX_WAITV_MAX 128
#endif

struct futex_waitv_local {
	uint64_t val;
	uint64_t uaddr;
	uint32_t flags;
	uint32_t __reserved;
};

/* Mount API */
#ifndef MOUNT_ATTR_SIZE_VER0
#define MOUNT_ATTR_SIZE_VER0 32
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000
#endif

#ifndef MOUNT_ATTR_NOSYMFOLLOW
#define MOUNT_ATTR_NOSYMFOLLOW 0x00200000
#endif

struct mount_attr_local {
	uint64_t attr_set;
	uint64_t attr_clr;
	uint64_t propagation;
	uint64_t userns_fd;
};

/* Quota Syscall (quotactl_fd) */
#ifndef QCMD
#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define QCMD(cmd, type) (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))
#endif

#ifndef USRQUOTA
#define USRQUOTA 0
#endif
#ifndef GRPQUOTA
#define GRPQUOTA 1
#endif
#ifndef Q_GETQUOTA
#define Q_GETQUOTA 0x800007
#endif
#ifndef Q_SYNC
#define Q_SYNC     0x800001
#endif

/* ========================================================================= */
/* Binder IPC Driver UAPI Definitions                                        */
/* ========================================================================= */

#define BINDER_CURRENT_PROTOCOL_VERSION 8

struct binder_version_local {
	signed long protocol_version;
};

struct binder_write_read_local {
	uint64_t write_size;
	uint64_t write_consumed;
	uint64_t write_buffer;
	uint64_t read_size;
	uint64_t read_consumed;
	uint64_t read_buffer;
};

#define BINDER_WRITE_READ_LOCAL       _IOWR('b', 1, struct binder_write_read_local)
#define BINDER_SET_MAX_THREADS_LOCAL  _IOW('b', 5, uint32_t)
#define BINDER_VERSION_LOCAL          _IOWR('b', 9, struct binder_version_local)

#define BC_ENTER_LOOPER_LOCAL         _IO('c', 12)
#define BC_EXIT_LOOPER_LOCAL          _IO('c', 13)

#endif /* TEST_UAPI_H */
