CLANG ?= clang
CFLAGS ?= -O2 -Wall -Wextra -pthread -Iinclude

SRCS = $(wildcard src/*.c)
HDRS = $(wildcard include/*.h)

MUSL_AARCH64_SYSROOT ?= /usr/aarch64-linux-musl
MUSL_AARCH64_LIB     ?= $(MUSL_AARCH64_SYSROOT)/lib/musl/lib
MUSL_AARCH64_INC     ?= $(MUSL_AARCH64_SYSROOT)/lib/musl/include
GCC_AARCH64_LIB      ?= /usr/lib/gcc/aarch64-linux-gnu/16.1.0

AARCH64_CLANG_FLAGS  = --target=aarch64-linux-musl \
                       -fuse-ld=lld \
                       -isystem $(MUSL_AARCH64_INC) \
                       -B$(MUSL_AARCH64_LIB) -L$(MUSL_AARCH64_LIB) \
                       -B$(GCC_AARCH64_LIB) -L$(GCC_AARCH64_LIB) \
                       -static

all: arm64 host

arm64: test_backports_arm64

test_backports_arm64: $(SRCS) $(HDRS)
	$(CLANG) $(AARCH64_CLANG_FLAGS) $(CFLAGS) $(SRCS) -o $@

host: test_backports_host

test_backports_host: $(SRCS) $(HDRS)
	musl-clang -static $(CFLAGS) $(SRCS) -o $@ || $(CLANG) -static $(CFLAGS) $(SRCS) -o $@

clean:
	rm -f test_backports_arm64 test_backports_host

device: arm64
	./run_device_test.sh $(ARGS)

.PHONY: all arm64 host device clean
