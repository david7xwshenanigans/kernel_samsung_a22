# Bugfix Audit Report — Android 4.14 a22

## Tree
- Version string: 4.14.186
- Compiler: clang
- Defconfig: a22_defconfig
- Audit date: 2026-03-23

## Findings

| # | Tag | File | Line | Bug Class | Severity | Commit |
|---|---|---|---|---|---|---|
| 1 | backport | kernel/sched/fair.c | 3034 | Syntax error | CRITICAL | (Pending) |
| 2 | 4.14-native | mm/vmscan.c | 19 | Missing Header Include | CRITICAL | (Pending) |
| 3 | mtk-vendor | drivers/char/rpmb/rpmb-mtk.c | 553 | API mismatch | CRITICAL | (Pending) |

## BPF Changes (if any)
None.

## Ambiguous Findings (not fixed)
None.

## Known regressions introduced
None.
