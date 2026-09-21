#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>

/* Terminal Color Codes */
#define ANSI_RESET   "\033[0m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_BOLD    "\033[1m"

/* Global Test Statistics */
extern int g_total_tests;
extern int g_passed_tests;
extern int g_failed_tests;
extern int g_skipped_tests;

/* Test Reporting API */
void report_pass(const char *module, const char *test_name);
void report_fail(const char *module, const char *test_name, const char *fmt, ...);
void report_skip(const char *module, const char *test_name, const char *fmt, ...);
void report_base_skip(const char *module, const char *feature_name);
void report_info(const char *fmt, ...);
bool is_root(void);

/* Base Feature Existence Guard */
#define CHECK_BASE_OR_SKIP(condition, module, feature_name) \
	do { \
		if (!(condition)) { \
			report_base_skip((module), (feature_name)); \
			return; \
		} \
	} while (0)

/* Test Suite Definition & Registration */
typedef struct {
	const char *name;
	const char *description;
	void (*run)(void);
} test_suite_t;

void register_test_suite(const char *name, const char *description, void (*run)(void));
void list_test_suites(void);
int run_test_suites(const char *target_suite);

#endif /* TEST_FRAMEWORK_H */
