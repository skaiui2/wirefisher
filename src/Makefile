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
OBJS        := $(SRCS:.c=.o)

.PHONY: all clean

all: $(OBJS)

# 自动生成 vmlinux.h
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 编译规则，依赖 vmlinux.h
%.o: %.c vmlinux.h common.h
	$(CC) $(BPF_CFLAGS) $(PKG_CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) vmlinux.h

