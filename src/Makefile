
# 目标架构 & headers
ARCH       := x86_64
KHEAD      := $(CURDIR)/kernel-headers/include

# 编译器 & 选项
CC         := clang
BPF_CFLAGS := -O2 -g -target bpf
PKG_CFLAGS := $(shell pkg-config --cflags libbpf)

INCLUDES   := \
    -I$(KHEAD) \
    -I/usr/include \
    -I/usr/include/$(shell dpkg-architecture -q DEB_HOST_MULTIARCH)

.PHONY: all clean

all: tc_process.o

tc_process.o: tc_process.c
	$(CC) $(BPF_CFLAGS) $(PKG_CFLAGS) $(INCLUDES) \
		-c $< -o $@

clean:
	rm -f tc_process.o

