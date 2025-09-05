ARCH        := x86_64
KHEAD       := $(CURDIR)/kernel-headers/include

CC          := clang
BPF_CFLAGS  := -O2 -g -target bpf -Wno-unknown-attributes
PKG_CFLAGS  := $(shell pkg-config --cflags libbpf)

INCLUDES    := \
	-I$(KHEAD) \
	-I/usr/include \
	-I/usr/include/$(shell dpkg-architecture -q DEB_HOST_MULTIARCH)

SRCS        := $(wildcard tc_*.c)
BUILD_DIR   := build
OBJS        := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean

all: $(BUILD_DIR) vmlinux.h $(OBJS)

# 创建 build 目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 自动生成 vmlinux.h
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 编译规则：将 .o 文件输出到 build/
$(BUILD_DIR)/%.o: %.c vmlinux.h common.h
	$(CC) $(BPF_CFLAGS) $(PKG_CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) vmlinux.h

