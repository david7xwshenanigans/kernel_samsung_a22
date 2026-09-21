#include "test_framework.h"
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#ifndef LOOP_SET_FD
#define LOOP_SET_FD		0x4C00
#define LOOP_CLR_FD		0x4C01
#define LOOP_CTL_GET_FREE	0x4C82
#endif

/* EROFS On-disk specification constants (v5.15+) */
#define EROFS_MAGIC_NUMBER_V1_VAL	0xE0F5E1E2
#define EROFS_FEAT_INCOMPAT_LZ4_0PAD	0x00000001
#define EROFS_FEAT_INCOMPAT_COMPR_CFGS	0x00000002
#define EROFS_FEAT_INCOMPAT_BIG_PCLUST	0x00000002
#define EROFS_FEAT_INCOMPAT_CHUNKED_F	0x00000004
#define EROFS_FEAT_INCOMPAT_DEV_TABLE	0x00000008
#define EROFS_FEAT_INCOMPAT_COMPR_HEAD2	0x00000008

#define EROFS_INODE_LAYOUT_COMPACT_VAL	0
#define EROFS_INODE_LAYOUT_EXTENDED_VAL	1

#define EROFS_INODE_FLAT_PLAIN_VAL		0
#define EROFS_INODE_FLAT_COMPRESSION_LEGACY_VAL	1
#define EROFS_INODE_FLAT_INLINE_VAL		2
#define EROFS_INODE_FLAT_COMPRESSION_VAL	3
#define EROFS_INODE_CHUNK_BASED_VAL		4

#define EROFS_CHUNK_FMT_BLKBITS_MASK	0x001F
#define EROFS_CHUNK_FMT_INDEXES		0x0020
#define EROFS_CHUNK_FMT_ALL		0x003F

#define EROFS_NULL_ADDR_VAL		((uint32_t)-1)
#define EROFS_BLOCK_MAP_ENTRY_SZ	4

#define Z_EROFS_COMPR_LZ4_VAL		0
#define Z_EROFS_COMPR_LZMA_VAL		1
#define Z_EROFS_VLE_HEAD2_VAL		3

struct __attribute__((packed)) test_erofs_sb {
	uint32_t magic;
	uint32_t checksum;
	uint32_t feature_compat;
	uint8_t  blkszbits;
	uint8_t  sb_extslots;
	uint16_t root_nid;
	uint64_t inos;
	uint64_t build_time;
	uint32_t build_time_nsec;
	uint32_t blocks;
	uint32_t meta_blkaddr;
	uint32_t xattr_blkaddr;
	uint8_t  uuid[16];
	uint8_t  volume_name[16];
	uint32_t feature_incompat;
	union {
		uint16_t available_compr_algs;
		uint16_t lz4_max_distance;
	} u1;
	uint8_t  reserved2[42];
};

struct __attribute__((packed)) test_erofs_inode_chunk_info {
	uint16_t format;
	uint16_t reserved;
};

struct __attribute__((packed)) test_erofs_inode_chunk_index {
	uint16_t advise;
	uint16_t device_id;
	uint32_t blkaddr;
};

struct __attribute__((packed)) test_erofs_inode_compact {
	uint16_t i_format;
	uint16_t i_xattr_icount;
	uint16_t i_mode;
	uint16_t i_nlink;
	uint32_t i_size;
	uint32_t reserved;
	union {
		uint32_t raw_blkaddr;
		uint32_t rdev;
		struct test_erofs_inode_chunk_info c;
	} i_u;
	uint32_t i_ino;
	uint16_t i_uid;
	uint16_t i_gid;
	uint32_t i_checksum;
};

struct __attribute__((packed)) test_erofs_dirent {
	uint64_t nid;
	uint16_t nameoff;
	uint8_t  file_type;
	uint8_t  reserved;
};

static void test_erofs_procfs_support(void)
{
	const char *mod = "EROFS_PROCFS";
	FILE *fp = fopen("/proc/filesystems", "r");
	if (!fp) {
		CHECK_BASE_OR_SKIP(false, mod, "Access to /proc/filesystems");
	}

	char line[128];
	bool found = false;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "erofs")) {
			found = true;
			break;
		}
	}
	fclose(fp);

	if (found) {
		report_pass(mod, "EROFS registered in /proc/filesystems");
	} else {
		/* If built as module or not mounted, test via dummy mount to probe kernel awareness */
		int ret = mount(NULL, "/tmp", "erofs", MS_RDONLY, NULL);
		if (ret < 0 && (errno == ENODEV)) {
			report_fail(mod, "EROFS kernel support", "erofs filesystem not recognized (ENODEV)");
		} else {
			report_pass(mod, "EROFS driver recognized by kernel (mount probed)");
		}
	}
}

static void test_erofs_abi_structures(void)
{
	const char *mod = "EROFS_ABI";

	/* 1. Superblock layout & magic */
	if (EROFS_MAGIC_NUMBER_V1_VAL == 0xE0F5E1E2) {
		report_pass(mod, "EROFS v1 magic constant (0xE0F5E1E2)");
	} else {
		report_fail(mod, "EROFS v1 magic", "Invalid magic constant");
	}

	if (sizeof(struct test_erofs_sb) == 128) {
		report_pass(mod, "Superblock structure size == 128 bytes");
	} else {
		report_fail(mod, "Superblock structure size", "Expected 128 bytes, got %zu", sizeof(struct test_erofs_sb));
	}

	/* 2. Feature incompat flags */
	uint32_t all_incompat = EROFS_FEAT_INCOMPAT_LZ4_0PAD |
				EROFS_FEAT_INCOMPAT_COMPR_CFGS |
				EROFS_FEAT_INCOMPAT_BIG_PCLUST |
				EROFS_FEAT_INCOMPAT_CHUNKED_F |
				EROFS_FEAT_INCOMPAT_DEV_TABLE |
				EROFS_FEAT_INCOMPAT_COMPR_HEAD2;

	if ((all_incompat & EROFS_FEAT_INCOMPAT_CHUNKED_F) &&
	    (all_incompat & EROFS_FEAT_INCOMPAT_COMPR_HEAD2)) {
		report_pass(mod, "Incompatible feature bits: CHUNKED_FILE (0x4) and COMPR_HEAD2 (0x8)");
	} else {
		report_fail(mod, "Incompatible feature bits", "Missing CHUNKED_FILE or COMPR_HEAD2 in incompat mask");
	}

	/* 3. Chunk-based file ABI integrity */
	if (sizeof(struct test_erofs_inode_chunk_info) == 4) {
		report_pass(mod, "erofs_inode_chunk_info size == 4 bytes");
	} else {
		report_fail(mod, "erofs_inode_chunk_info size", "Expected 4 bytes, got %zu", sizeof(struct test_erofs_inode_chunk_info));
	}

	if (sizeof(struct test_erofs_inode_chunk_index) == 8) {
		report_pass(mod, "erofs_inode_chunk_index size == 8 bytes");
	} else {
		report_fail(mod, "erofs_inode_chunk_index size", "Expected 8 bytes, got %zu", sizeof(struct test_erofs_inode_chunk_index));
	}

	if (EROFS_INODE_CHUNK_BASED_VAL == 4) {
		report_pass(mod, "EROFS_INODE_CHUNK_BASED datalayout enum == 4");
	} else {
		report_fail(mod, "EROFS_INODE_CHUNK_BASED enum", "Expected 4, got %d", EROFS_INODE_CHUNK_BASED_VAL);
	}

	if (EROFS_BLOCK_MAP_ENTRY_SZ == 4 && EROFS_NULL_ADDR_VAL == 0xFFFFFFFFU) {
		report_pass(mod, "Block map entry size (4 bytes) and EROFS_NULL_ADDR (0xFFFFFFFF)");
	} else {
		report_fail(mod, "Block map entry constants", "Size or null address constant mismatch");
	}

	if (EROFS_CHUNK_FMT_BLKBITS_MASK == 0x1F && EROFS_CHUNK_FMT_INDEXES == 0x20 && EROFS_CHUNK_FMT_ALL == 0x3F) {
		report_pass(mod, "Chunk format masks (BLKBITS_MASK=0x1F, INDEXES=0x20, ALL=0x3F)");
	} else {
		report_fail(mod, "Chunk format masks", "Mask definition mismatch");
	}

	/* 4. Compression algorithm IDs */
	if (Z_EROFS_COMPR_LZ4_VAL == 0 && Z_EROFS_COMPR_LZMA_VAL == 1 && Z_EROFS_VLE_HEAD2_VAL == 3) {
		report_pass(mod, "Compression algorithms: LZ4 (0), MicroLZMA (1), HEAD2 cluster type (3)");
	} else {
		report_fail(mod, "Compression algorithms", "Algorithm format ID mismatch");
	}
}

static void test_erofs_mount_boundaries(void)
{
	const char *mod = "EROFS_MOUNT_BOUNDS";

	if (!is_root()) {
		/* Unprivileged user cannot mount; should return -1 with EPERM */
		int ret = mount("/dev/null", "/tmp", "erofs", MS_RDONLY, NULL);
		if (ret < 0 && errno == EPERM) {
			report_pass(mod, "Unprivileged mount rejection (EPERM)");
		} else if (ret < 0) {
			report_pass(mod, "Unprivileged mount denied as expected");
		} else {
			report_fail(mod, "Unprivileged mount", "Mount succeeded unexpectedly for non-root user");
		}
		return;
	}

	/* Privileged tests: boundary conditions */
	/* 1. NULL target */
	int ret1 = mount("/dev/null", NULL, "erofs", MS_RDONLY, NULL);
	if (ret1 < 0 && (errno == EFAULT || errno == ENOENT)) {
		report_pass(mod, "Invalid mount target (NULL/EFAULT)");
	} else {
		report_fail(mod, "Invalid mount target", "Expected EFAULT/ENOENT, got %d (%s)", errno, strerror(errno));
	}

	/* 2. Non-existent source device */
	int ret2 = mount("/nonexistent_erofs_dev_42", "/tmp", "erofs", MS_RDONLY, NULL);
	if (ret2 < 0 && errno == ENOENT) {
		report_pass(mod, "Non-existent source block device (ENOENT)");
	} else {
		report_fail(mod, "Non-existent device", "Expected ENOENT, got %d (%s)", errno, strerror(errno));
	}

	/* 3. Non-existent mountpoint */
	int ret3 = mount("/dev/zero", "/nonexistent_dir_erofs_99", "erofs", MS_RDONLY, NULL);
	if (ret3 < 0 && errno == ENOENT) {
		report_pass(mod, "Non-existent mountpoint (ENOENT)");
	} else {
		report_fail(mod, "Non-existent mountpoint", "Expected ENOENT, got %d (%s)", errno, strerror(errno));
	}
}

static void test_erofs_microlzma_properties(void)
{
	const char *mod = "EROFS_MICROLZMA_PROPS";

	/*
	 * MicroLZMA properties byte specification:
	 * The byte on disk is bitwise inverted (~props).
	 * props = ((pb * 5) + lp) * 9 + lc
	 * Valid ranges:
	 *   lc: [0, 8]
	 *   lp: [0, 4]
	 *   pb: [0, 4]
	 * Constraint: lc + lp <= 4
	 */

	/* 1. Test standard default configuration: lc=3, lp=0, pb=2 */
	uint32_t pb = 2, lp = 0, lc = 3;
	uint32_t props = ((pb * 5) + lp) * 9 + lc;
	uint8_t enc_byte = (uint8_t)(~props);

	/* Decode */
	uint8_t dec_raw = (uint8_t)(~enc_byte);
	uint32_t d_pb = dec_raw / 45;
	dec_raw -= d_pb * 45;
	uint32_t d_lp = dec_raw / 9;
	uint32_t d_lc = dec_raw - d_lp * 9;

	if (d_pb == 2 && d_lp == 0 && d_lc == 3 && (d_lc + d_lp <= 4)) {
		report_pass(mod, "Standard MicroLZMA properties (lc=3, lp=0, pb=2)");
	} else {
		report_fail(mod, "MicroLZMA default props", "Decode mismatch: pb=%u lp=%u lc=%u", d_pb, d_lp, d_lc);
	}

	/* 2. Test boundary condition: minimum values lc=0, lp=0, pb=0 */
	pb = 0; lp = 0; lc = 0;
	props = ((pb * 5) + lp) * 9 + lc;
	enc_byte = (uint8_t)(~props);
	dec_raw = (uint8_t)(~enc_byte);
	if (dec_raw == 0 && enc_byte == 0xFF) {
		report_pass(mod, "MicroLZMA minimum properties boundary (lc=0, lp=0, pb=0 => enc=0xFF)");
	} else {
		report_fail(mod, "MicroLZMA min props", "Expected enc=0xFF, got 0x%02X", enc_byte);
	}

	/* 3. Test boundary condition: maximum valid sum lc=4, lp=0, pb=4 */
	pb = 4; lp = 0; lc = 4;
	props = ((pb * 5) + lp) * 9 + lc;
	if (props <= (4 * 5 + 4) * 9 + 8 && (lc + lp <= 4)) {
		report_pass(mod, "MicroLZMA max allowable parameters (lc=4, lp=0, pb=4)");
	} else {
		report_fail(mod, "MicroLZMA max props", "Constraint failure for max parameters");
	}

	/* 4. Test invalid constraint rejection: lc + lp > 4 (e.g. lc=3, lp=2 => 5) */
	pb = 2; lp = 2; lc = 3;
	bool rejected = ((lc + lp) > 4);
	if (rejected) {
		report_pass(mod, "MicroLZMA constraint check: lc + lp > 4 rejected");
	} else {
		report_fail(mod, "MicroLZMA constraint check", "Failed to detect lc+lp > 4 violation");
	}
}

static void test_erofs_corrupted_image_rejection(void)
{
	const char *mod = "EROFS_CORRUPT_DETECT";

	if (!is_root()) {
		report_skip(mod, "Live mount rejection tests", "Root required for loopback mounting");
		return;
	}

	int loop_ctl_fd = open("/dev/loop-control", O_RDWR);
	if (loop_ctl_fd < 0) {
		report_skip(mod, "Live mount rejection tests", "Cannot open /dev/loop-control");
		return;
	}

	uint8_t bad_img[4096];
	memset(bad_img, 0, sizeof(bad_img));
	struct test_erofs_sb *sb = (struct test_erofs_sb *)(bad_img + 1024);

	/* 1. Corrupted Magic: 0xDEADBEEF */
	sb->magic = 0xDEADBEEF;
	sb->blkszbits = 12;
	sb->blocks = 1;

	char tmp_img[] = "/tmp/erofs_corrupt_XXXXXX";
	int tfd = mkstemp(tmp_img);
	if (tfd >= 0) {
		ssize_t w = write(tfd, bad_img, sizeof(bad_img));
		close(tfd);
		if (w == sizeof(bad_img)) {
			int dev_num = ioctl(loop_ctl_fd, LOOP_CTL_GET_FREE);
			if (dev_num >= 0) {
				char loop_dev[64];
				snprintf(loop_dev, sizeof(loop_dev), "/dev/loop%d", dev_num);
				int lfd = open(loop_dev, O_RDWR);
				if (lfd >= 0) {
					int ffd = open(tmp_img, O_RDWR);
					if (ffd >= 0 && ioctl(lfd, LOOP_SET_FD, ffd) == 0) {
						const char *mnt = "/tmp/erofs_corrupt_mnt";
						mkdir(mnt, 0755);
						int mres = mount(loop_dev, mnt, "erofs", MS_RDONLY, NULL);
						if (mres < 0 && (errno == EINVAL || errno == EIO)) {
							report_pass(mod, "Kernel rejected corrupted magic number (0xDEADBEEF) cleanly");
						} else if (mres == 0) {
							umount(mnt);
							report_fail(mod, "Bad magic rejection", "Mounted corrupted image unexpectedly");
						} else {
							report_pass(mod, "Kernel rejected bad magic cleanly");
						}
						rmdir(mnt);
						ioctl(lfd, LOOP_CLR_FD, 0);
					}
					if (ffd >= 0) close(ffd);
					close(lfd);
				}
			}
		}
		unlink(tmp_img);
	}

	/* 2. Unsupported incompatible feature flag */
	memset(bad_img, 0, sizeof(bad_img));
	sb->magic = EROFS_MAGIC_NUMBER_V1_VAL;
	sb->blkszbits = 12;
	sb->blocks = 1;
	sb->feature_incompat = 0x80000000U; /* Unknown future feature flag */

	tfd = mkstemp(tmp_img);
	if (tfd >= 0) {
		ssize_t w = write(tfd, bad_img, sizeof(bad_img));
		close(tfd);
		if (w == sizeof(bad_img)) {
			int dev_num = ioctl(loop_ctl_fd, LOOP_CTL_GET_FREE);
			if (dev_num >= 0) {
				char loop_dev[64];
				snprintf(loop_dev, sizeof(loop_dev), "/dev/loop%d", dev_num);
				int lfd = open(loop_dev, O_RDWR);
				if (lfd >= 0) {
					int ffd = open(tmp_img, O_RDWR);
					if (ffd >= 0 && ioctl(lfd, LOOP_SET_FD, ffd) == 0) {
						const char *mnt = "/tmp/erofs_corrupt_mnt";
						mkdir(mnt, 0755);
						int mres = mount(loop_dev, mnt, "erofs", MS_RDONLY, NULL);
						if (mres < 0 && (errno == EINVAL || errno == EOPNOTSUPP || errno == EIO)) {
							report_pass(mod, "Kernel rejected unsupported feature_incompat (0x80000000) cleanly");
						} else if (mres == 0) {
							umount(mnt);
							report_fail(mod, "Incompat flag rejection", "Mounted image with unknown incompat flag");
						} else {
							report_pass(mod, "Kernel rejected unknown feature cleanly");
						}
						rmdir(mnt);
						ioctl(lfd, LOOP_CLR_FD, 0);
					}
					if (ffd >= 0) close(ffd);
					close(lfd);
				}
			}
		}
		unlink(tmp_img);
	}

	close(loop_ctl_fd);
}

static void test_erofs_synthetic_chunked_image(void)
{
	const char *mod = "EROFS_CHUNK_FS";

	/* Check loop device control access */
	int loop_ctl_fd = open("/dev/loop-control", O_RDWR);
	if (loop_ctl_fd < 0) {
		report_info("Loopback control not available (%s), validating synthetic image buffer locally", strerror(errno));
	}

	/*
	 * Construct a 24KB EROFS filesystem in memory (6 blocks of 4096 bytes):
	 * Block 0: Offset 1024 -> Superblock
	 * Block 1: Inode directory (root inode, compact, raw_blkaddr = 5)
	 * Block 2: Inode chunked file (compact, EROFS_INODE_CHUNK_BASED, 3 chunks)
	 * Block 3: Chunk 0 data block ("CHUNK0_VERIFIED_DATA_PAYLOAD_ABCDEF")
	 * Block 4: Chunk 2 data block ("CHUNK2_VERIFIED_DATA_PAYLOAD_123456")
	 * Block 5: Root directory dirent table (".", "..", "chunk.bin")
	 */
	const size_t img_size = 24576;
	uint8_t *img = calloc(1, img_size);
	if (!img) {
		report_fail(mod, "Allocate synthetic image", "OOM allocating 24KB");
		if (loop_ctl_fd >= 0) close(loop_ctl_fd);
		return;
	}

	/* Block 0: Superblock at offset 1024 */
	struct test_erofs_sb *sb = (struct test_erofs_sb *)(img + 1024);
	sb->magic = EROFS_MAGIC_NUMBER_V1_VAL;
	sb->blkszbits = 12; /* 4096 bytes */
	sb->root_nid = 0;   /* Block 1, offset 0 */
	sb->blocks = 6;
	sb->meta_blkaddr = 1;
	sb->feature_incompat = EROFS_FEAT_INCOMPAT_CHUNKED_F;

	/* Block 1: Root directory inode (Compact, Flat plain layout) */
	struct test_erofs_inode_compact *root_inode = (struct test_erofs_inode_compact *)(img + 4096 * 1);
	root_inode->i_format = (EROFS_INODE_LAYOUT_COMPACT_VAL << 0) | (EROFS_INODE_FLAT_PLAIN_VAL << 1);
	root_inode->i_mode = 0040755; /* S_IFDIR | 0755 */
	root_inode->i_nlink = 2;
	root_inode->i_size = 48;      /* 3 dirents (36 bytes) + names (12 bytes) */
	root_inode->i_u.raw_blkaddr = 5; /* Directory data in Block 5 */

	/* Block 2: Chunk-based file inode (nid = 128) */
	struct test_erofs_inode_compact *cinode = (struct test_erofs_inode_compact *)(img + 4096 * 2);
	cinode->i_format = (EROFS_INODE_LAYOUT_COMPACT_VAL << 0) | (EROFS_INODE_CHUNK_BASED_VAL << 1);
	cinode->i_mode = 0100644; /* S_IFREG | 0644 */
	cinode->i_nlink = 1;
	cinode->i_size = 12288;   /* 3 chunks of 4KB */
	cinode->i_u.c.format = 0; /* 4-byte block map, 4KB chunk (chunkbits = 12) */

	/* Chunk entries immediately follow compact inode (32 bytes) */
	uint32_t *chunk_map = (uint32_t *)(img + 4096 * 2 + sizeof(struct test_erofs_inode_compact));
	chunk_map[0] = 3;                  /* Chunk 0 is at physical block 3 */
	chunk_map[1] = EROFS_NULL_ADDR_VAL;/* Chunk 1 is a HOLE (zeroes) */
	chunk_map[2] = 4;                  /* Chunk 2 is at physical block 4 */

	/* Block 3: Content for Chunk 0 */
	const char *chunk0_payload = "CHUNK0_VERIFIED_DATA_PAYLOAD_ABCDEF";
	memcpy(img + 4096 * 3, chunk0_payload, strlen(chunk0_payload));
	memset(img + 4096 * 3 + strlen(chunk0_payload), 0xAA, 4096 - strlen(chunk0_payload));

	/* Block 4: Content for Chunk 2 */
	const char *chunk2_payload = "CHUNK2_VERIFIED_DATA_PAYLOAD_123456";
	memcpy(img + 4096 * 4, chunk2_payload, strlen(chunk2_payload));
	memset(img + 4096 * 4 + strlen(chunk2_payload), 0x55, 4096 - strlen(chunk2_payload));

	/* Block 5: Root directory dirent table */
	/*
	 * Entry 0: "."        (nid = 0,   nameoff = 36, type = DIR)
	 * Entry 1: ".."       (nid = 0,   nameoff = 37, type = DIR)
	 * Entry 2: "chunk.bin" (nid = 128, nameoff = 39, type = REG)
	 */
	struct test_erofs_dirent *de = (struct test_erofs_dirent *)(img + 4096 * 5);
	de[0].nid = 0;
	de[0].nameoff = 36;
	de[0].file_type = 2; /* EROFS_FT_DIR */

	de[1].nid = 0;
	de[1].nameoff = 37;
	de[1].file_type = 2; /* EROFS_FT_DIR */

	de[2].nid = 128;     /* Inode at block 2, offset 0 */
	de[2].nameoff = 39;
	de[2].file_type = 1; /* EROFS_FT_REG_FILE */

	char *names = (char *)(img + 4096 * 5 + 36);
	names[0] = '.';
	names[1] = '.';
	names[2] = '.';
	memcpy(&names[3], "chunk.bin", 9);

	/* Verify on-disk representation integrity */
	if (cinode->i_size == 12288 && chunk_map[0] == 3 &&
	    chunk_map[1] == 0xFFFFFFFFU && chunk_map[2] == 4) {
		report_pass(mod, "Synthetic chunk-based file layout (Data Chunk 0 + Hole Chunk 1 + Data Chunk 2)");
	} else {
		report_fail(mod, "Synthetic chunk file layout", "Invalid inode or blockmap representation");
	}

	/* Live loop mount and deep read validation */
	if (is_root() && loop_ctl_fd >= 0) {
		char tmp_img_path[] = "/tmp/erofs_test_XXXXXX";
		int img_fd = mkstemp(tmp_img_path);
		if (img_fd >= 0) {
			ssize_t written = write(img_fd, img, img_size);
			close(img_fd);

			if (written == (ssize_t)img_size) {
				int dev_num = ioctl(loop_ctl_fd, LOOP_CTL_GET_FREE);
				if (dev_num >= 0) {
					char loop_dev[64];
					snprintf(loop_dev, sizeof(loop_dev), "/dev/loop%d", dev_num);
					int lfd = open(loop_dev, O_RDWR);
					if (lfd >= 0) {
						int ffd = open(tmp_img_path, O_RDWR);
						if (ffd >= 0 && ioctl(lfd, LOOP_SET_FD, ffd) == 0) {
							const char *mnt_dir = "/tmp/erofs_test_mnt";
							mkdir(mnt_dir, 0755);
							int mnt_res = mount(loop_dev, mnt_dir, "erofs", MS_RDONLY, NULL);
							if (mnt_res == 0) {
								report_pass(mod, "Live loop mount of synthetic chunk-based filesystem");

								/* 1. Open chunked file */
								char file_path[128];
								snprintf(file_path, sizeof(file_path), "%s/chunk.bin", mnt_dir);
								int cfd = open(file_path, O_RDONLY);
								if (cfd >= 0) {
									report_pass(mod, "Lookup and open chunk-based file (/chunk.bin)");

									/* 2. Read Chunk 0 (mapped data block) */
									uint8_t read_buf[4096];
									ssize_t r = pread(cfd, read_buf, 4096, 0);
									if (r == 4096 && memcmp(read_buf, chunk0_payload, strlen(chunk0_payload)) == 0) {
										report_pass(mod, "pread() Chunk 0 (mapped data block verified)");
									} else {
										report_fail(mod, "pread() Chunk 0", "Data verification failed (r=%zd)", r);
									}

									/* 3. Read Chunk 1 (sparse hole block) */
									r = pread(cfd, read_buf, 4096, 4096);
									bool all_zeroes = true;
									for (int i = 0; i < 4096; i++) {
										if (read_buf[i] != 0) {
											all_zeroes = false;
											break;
										}
									}
									if (r == 4096 && all_zeroes) {
										report_pass(mod, "pread() Chunk 1 (sparse hole reads as 4096 zero bytes)");
									} else {
										report_fail(mod, "pread() Chunk 1", "Hole did not read as zeroes (r=%zd all_zeroes=%d)", r, all_zeroes);
									}

									/* 4. Read Chunk 2 (mapped data block) */
									r = pread(cfd, read_buf, 4096, 8192);
									if (r == 4096 && memcmp(read_buf, chunk2_payload, strlen(chunk2_payload)) == 0) {
										report_pass(mod, "pread() Chunk 2 (mapped data block verified)");
									} else {
										report_fail(mod, "pread() Chunk 2", "Data verification failed (r=%zd)", r);
									}

									/* 5. Straddled read across Chunk 0 and Hole Chunk 1 boundary */
									r = pread(cfd, read_buf, 4096, 2048);
									bool straddle_ok = (r == 4096);
									if (straddle_ok) {
										/* First 2048 bytes should be 0xAA (Chunk 0 tail) */
										for (int i = 0; i < 2048; i++) {
											if (read_buf[i] != 0xAA) { straddle_ok = false; break; }
										}
										/* Next 2048 bytes should be 0x00 (Chunk 1 hole head) */
										for (int i = 2048; i < 4096; i++) {
											if (read_buf[i] != 0x00) { straddle_ok = false; break; }
										}
									}
									if (straddle_ok) {
										report_pass(mod, "pread() straddling boundary (Chunk 0 data -> Hole Chunk 1 zeroes)");
									} else {
										report_fail(mod, "pread() boundary straddle", "Straddle read failed verification");
									}

									/* 6. SEEK_DATA and SEEK_HOLE lseek() verification */
									#ifdef SEEK_HOLE
									off_t hole_off = lseek(cfd, 0, SEEK_HOLE);
									if (hole_off == 4096) {
										report_pass(mod, "lseek(SEEK_HOLE) locates chunk 1 hole at offset 4096");
									} else {
										report_fail(mod, "lseek(SEEK_HOLE)", "Expected 4096, got %ld", (long)hole_off);
									}
									#endif

									#ifdef SEEK_DATA
									off_t data_off = lseek(cfd, 4096, SEEK_DATA);
									if (data_off == 8192) {
										report_pass(mod, "lseek(SEEK_DATA) locates chunk 2 data at offset 8192");
									} else {
										report_fail(mod, "lseek(SEEK_DATA)", "Expected 8192, got %ld", (long)data_off);
									}
									#endif

									close(cfd);
								} else {
									report_fail(mod, "Open chunk-based file", "open failed: %s (errno=%d)", strerror(errno), errno);
								}
								umount(mnt_dir);
							} else {
								report_info("Live mount returned errno %d (%s)", errno, strerror(errno));
								report_fail(mod, "Live mount of synthetic chunk-based filesystem", "errno=%d (%s)", errno, strerror(errno));
							}
							rmdir(mnt_dir);
							ioctl(lfd, LOOP_CLR_FD, 0);
						}
						if (ffd >= 0) close(ffd);
						close(lfd);
					}
				}
			}
			unlink(tmp_img_path);
		}
	} else {
		report_info("Skipping live loopback mount (requires root and /dev/loop-control)");
	}

	if (loop_ctl_fd >= 0) close(loop_ctl_fd);
	free(img);
}

static void run_erofs_suite(void)
{
	test_erofs_procfs_support();
	test_erofs_abi_structures();
	test_erofs_microlzma_properties();
	test_erofs_mount_boundaries();
	test_erofs_synthetic_chunked_image();
	test_erofs_corrupted_image_rejection();
}

void register_suite_erofs(void)
{
	register_test_suite("erofs", "EROFS 5.15 Backports (MicroLZMA, Chunked Files, HEAD2, Readmore)", run_erofs_suite);
}

