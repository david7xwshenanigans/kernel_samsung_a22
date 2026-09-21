#include "test_framework.h"

int g_total_tests   = 0;
int g_passed_tests  = 0;
int g_failed_tests  = 0;
int g_skipped_tests = 0;

#define MAX_TEST_SUITES 64
static test_suite_t g_suites[MAX_TEST_SUITES];
static int g_num_suites = 0;

void register_test_suite(const char *name, const char *description, void (*run)(void))
{
	if (g_num_suites >= MAX_TEST_SUITES) {
		fprintf(stderr, "Error: Exceeded MAX_TEST_SUITES\n");
		return;
	}
	g_suites[g_num_suites].name = name;
	g_suites[g_num_suites].description = description;
	g_suites[g_num_suites].run = run;
	g_num_suites++;
}

void report_pass(const char *module, const char *test_name)
{
	g_total_tests++;
	g_passed_tests++;
	printf("%s[PASS]%s %-15s: %s\n", ANSI_GREEN, ANSI_RESET, module, test_name);
}

void report_fail(const char *module, const char *test_name, const char *fmt, ...)
{
	g_total_tests++;
	g_failed_tests++;
	printf("%s[FAIL]%s %-15s: %s -> ", ANSI_RED, ANSI_RESET, module, test_name);
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\n");
}

void report_skip(const char *module, const char *test_name, const char *fmt, ...)
{
	g_total_tests++;
	g_skipped_tests++;
	printf("%s[SKIP]%s %-15s: %s (", ANSI_YELLOW, ANSI_RESET, module, test_name);
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf(")\n");
}

void report_base_skip(const char *module, const char *feature_name)
{
	g_total_tests++;
	g_skipped_tests++;
	printf("%s[SKIP]%s %-15s: %s doesnt exist! Skipping... Are you on the right build?\n",
	       ANSI_YELLOW, ANSI_RESET, module, feature_name);
}

void report_info(const char *fmt, ...)
{
	printf("  * ");
	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	printf("\n");
}

bool is_root(void)
{
	return (geteuid() == 0);
}

void list_test_suites(void)
{
	printf("Available test suites (%d registered):\n", g_num_suites);
	for (int i = 0; i < g_num_suites; i++) {
		printf("  - %-18s : %s\n", g_suites[i].name, g_suites[i].description);
	}
}

int run_test_suites(const char *target_suite)
{
	int executed = 0;
	for (int i = 0; i < g_num_suites; i++) {
		if (target_suite && strcasecmp(target_suite, g_suites[i].name) != 0)
			continue;

		printf("\n--- [Suite: %s — %s] ---\n", g_suites[i].name, g_suites[i].description);
		g_suites[i].run();
		executed++;
	}

	if (target_suite && executed == 0) {
		fprintf(stderr, "%sError:%s Suite '%s' not found.\n", ANSI_RED, ANSI_RESET, target_suite);
		list_test_suites();
		return -1;
	}

	return 0;
}
