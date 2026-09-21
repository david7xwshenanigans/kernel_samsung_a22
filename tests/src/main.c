#include "test_framework.h"

/* Forward declarations for suite registration */
void register_suite_bpf(void);
void register_suite_dmabuf_heaps(void);
void register_suite_io_uring(void);
void register_suite_syscalls_core(void);
void register_suite_syscalls_mem(void);
void register_suite_syscalls_sync_fs(void);
void register_suite_procfs_vm(void);
void register_suite_erofs(void);
void register_suite_binder(void);

static void print_usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n", prog);
	printf("Options:\n");
	printf("  -s, --suite <name>  Run only the specified test suite\n");
	printf("  -l, --list          List all available test suites\n");
	printf("  -h, --help          Show this help message\n");
}

int main(int argc, char **argv)
{
	/* Register all available modular test suites */
	register_suite_bpf();
	register_suite_dmabuf_heaps();
	register_suite_io_uring();
	register_suite_syscalls_core();
	register_suite_syscalls_mem();
	register_suite_syscalls_sync_fs();
	register_suite_procfs_vm();
	register_suite_erofs();
	register_suite_binder();

	const char *target_suite = NULL;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
			list_test_suites();
			return 0;
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0]);
			return 0;
		} else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--suite") == 0) {
			if (i + 1 < argc) {
				target_suite = argv[++i];
			} else {
				fprintf(stderr, "Error: --suite requires an argument.\n");
				return 1;
			}
		} else {
			fprintf(stderr, "Unknown argument: %s\n", argv[i]);
			print_usage(argv[0]);
			return 1;
		}
	}

	printf("===================================================================\n");
	printf("%s   Samsung A22 Backports & Subsystems Comprehensive Test Suite   %s\n", ANSI_BOLD, ANSI_RESET);
	printf("   Target: arm64 (MediaTek MT6768) Linux 4.14 Subsystem Backports   \n");
	printf("===================================================================\n");
	report_info("Execution user: %s (UID=%d, GID=%d)", is_root() ? "root" : "unprivileged", geteuid(), getegid());

	if (run_test_suites(target_suite) != 0)
		return 1;

	printf("\n===================================================================\n");
	printf("                        TEST SUMMARY REPORT                        \n");
	printf("===================================================================\n");
	printf("  Total Test Checks : %d\n", g_total_tests);
	printf("  %sPassed Tests%s      : %d\n", ANSI_GREEN, ANSI_RESET, g_passed_tests);
	printf("  %sFailed Tests%s      : %d\n", g_failed_tests > 0 ? ANSI_RED : ANSI_GREEN, ANSI_RESET, g_failed_tests);
	printf("  %sSkipped Tests%s     : %d\n", ANSI_YELLOW, ANSI_RESET, g_skipped_tests);
	printf("===================================================================\n");

	if (g_failed_tests > 0) {
		printf("%s>> RESULTS: FAILURE (%d test checks failed)%s\n", ANSI_RED, g_failed_tests, ANSI_RESET);
		return 1;
	}

	printf("%s>> RESULTS: ALL TESTS PASSED%s\n", ANSI_GREEN, ANSI_RESET);
	return 0;
}
