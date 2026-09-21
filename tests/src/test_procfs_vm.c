#include "test_framework.h"
#include <fcntl.h>
#include <ctype.h>

static void test_procfs_smaps_rollup(void)
{
	const char *mod = "PROCFS_SMAPS";
	const char *path = "/proc/self/smaps_rollup";

	FILE *fp = fopen(path, "r");
	if (!fp) {
		CHECK_BASE_OR_SKIP(false, mod, "smaps_rollup (/proc/self/smaps_rollup)");
	}

	char line[256];
	bool found_rss = false;
	bool found_pss = false;
	bool found_pss_anon = false;
	bool found_pss_file = false;
	bool found_pss_shmem = false;

	long long val_pss = -1;
	long long val_pss_anon = -1;
	long long val_pss_file = -1;
	long long val_pss_shmem = -1;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "Rss:", 4) == 0) {
			found_rss = true;
		} else if (strncmp(line, "Pss:", 4) == 0) {
			found_pss = true;
			sscanf(line + 4, "%lld", &val_pss);
		} else if (strncmp(line, "Pss_Anon:", 9) == 0) {
			found_pss_anon = true;
			sscanf(line + 9, "%lld", &val_pss_anon);
		} else if (strncmp(line, "Pss_File:", 9) == 0) {
			found_pss_file = true;
			sscanf(line + 9, "%lld", &val_pss_file);
		} else if (strncmp(line, "Pss_Shmem:", 10) == 0) {
			found_pss_shmem = true;
			sscanf(line + 10, "%lld", &val_pss_shmem);
		}
	}
	fclose(fp);

	if (!found_rss || !found_pss) {
		report_fail(mod, "Read /proc/self/smaps_rollup", "Missing base Rss or Pss fields");
		return;
	}
	report_pass(mod, "Read /proc/self/smaps_rollup header and Pss");

	/* Verify backported split PSS components (commit 8a322e00d9556) */
	if (found_pss_anon && found_pss_file && found_pss_shmem) {
		report_pass(mod, "smaps_rollup provides split PSS components (Pss_Anon, Pss_File, Pss_Shmem)");
		report_info("smaps_rollup: Pss=%lld kB (Anon=%lld, File=%lld, Shmem=%lld)",
			    val_pss, val_pss_anon, val_pss_file, val_pss_shmem);

		/* Pss should equal sum of components within +/- 3 kB rounding error */
		long long sum = val_pss_anon + val_pss_file + val_pss_shmem;
		long long diff = val_pss > sum ? (val_pss - sum) : (sum - val_pss);
		if (diff <= 3) {
			report_pass(mod, "PSS split components arithmetic integrity (Pss == Anon + File + Shmem)");
		} else {
			report_fail(mod, "PSS split components arithmetic", "Pss=%lld != sum=%lld (diff=%lld)", val_pss, sum, diff);
		}
	} else {
		report_fail(mod, "smaps_rollup split PSS components",
			    "Missing fields: Pss_Anon=%d Pss_File=%d Pss_Shmem=%d",
			    found_pss_anon, found_pss_file, found_pss_shmem);
	}
}

static void test_vm_workingset_knobs(void)
{
	const char *mod = "VM_WORKING_SET";
	const char *knobs[] = {
		"/proc/sys/vm/anon_min_kbytes",
		"/proc/sys/vm/clean_low_kbytes",
		"/proc/sys/vm/clean_min_kbytes",
	};

	/* 1. Base Existence Check */
	if (access(knobs[0], F_OK) != 0 && errno == ENOENT) {
		CHECK_BASE_OR_SKIP(false, mod, "Working set protection sysctls (/proc/sys/vm/*_kbytes)");
	}

	for (size_t i = 0; i < sizeof(knobs) / sizeof(knobs[0]); i++) {
		FILE *fp = fopen(knobs[i], "r");
		if (!fp) {
			report_fail(mod, "Read sysctl knob", "Failed to open %s: %s", knobs[i], strerror(errno));
			continue;
		}

		long long val = -1;
		if (fscanf(fp, "%lld", &val) == 1 && val >= 0) {
			char pass_msg[128];
			snprintf(pass_msg, sizeof(pass_msg), "Read working-set knob: %s", knobs[i]);
			report_pass(mod, pass_msg);
			report_info("%s = %lld kB", knobs[i], val);
		} else {
			report_fail(mod, "Read working-set knob", "%s returned invalid value %lld", knobs[i], val);
		}
		fclose(fp);

		/* If root, test write and restore */
		if (is_root() && val >= 0) {
			int fd = open(knobs[i], O_WRONLY);
			if (fd >= 0) {
				char buf[64];
				snprintf(buf, sizeof(buf), "%lld\n", val);
				ssize_t written = write(fd, buf, strlen(buf));
				if (written == (ssize_t)strlen(buf)) {
					char write_msg[128];
					snprintf(write_msg, sizeof(write_msg), "Write validation to %s", knobs[i]);
					report_pass(mod, write_msg);
				} else {
					report_fail(mod, "Write validation", "%s write failed: %s", knobs[i], strerror(errno));
				}
				close(fd);
			}
		}
	}
}

static void run_procfs_vm_suite(void)
{
	test_procfs_smaps_rollup();
	test_vm_workingset_knobs();
}

void register_suite_procfs_vm(void)
{
	register_test_suite("procfs_vm", "Procfs & VM Backports (smaps_rollup PSS split, working set protection sysctls)", run_procfs_vm_suite);
}
