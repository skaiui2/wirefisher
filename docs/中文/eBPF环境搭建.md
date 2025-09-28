## 引言

考虑到eBPF环境本身搭建困难，写一写eBPF的环境搭建步骤。

**操作系统：Ubuntu25.04虚拟机**

## 环境搭建

### 更新系统并安装基础构建工具

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y build-essential git make cmake pkg-config \
  libelf-dev libbpf-dev bpfcc-tools libbpfcc-dev \
  libcap-dev binutils-dev libmnl-dev libnl-3-dev libnl-route-3-dev \
  linux-headers-$(uname -r) linux-tools-$(uname -r) linux-tools-common
```

 说明：

`libelf-dev`：用于解析 ELF 文件结构

`libbpf-dev`：用于构建 CO-RE 程序

`bpfcc-tools` / `libbpfcc-dev`：提供 BCC 工具链支持

`linux-tools-*`：包含 `perf`, `bpftool`, `trace` 等内核工具



## 安装 Clang/LLVM 工具链（匹配版本）

```bash
sudo apt install -y clang llvm lld libclang-dev llvm-dev libllvm17t64
```

注意：

Ubuntu 25.04 使用 T64 ABI，必须使用 `libllvm17t64` 而不是旧版 `libllvm`

`clang` 和 `llvm` 是编译 BPF 字节码的核心工具

`lld` 是 LLVM 的链接器，部分 CO-RE 示例依赖它

## 安装内核头文件并验证

```bash
sudo apt install -y linux-headers-$(uname -r)
```

验证头文件是否就绪：

```bash
ls /usr/include/asm/types.h
```

如果文件存在，说明头文件已正确安装，CO-RE 编译将能找到结构定义。

验证 bpftool 和 libbpf 是否可用

```bash
bpftool version
pkg-config --libs libbpf
```

如果 `bpftool` 不可用，可尝试：

```bash
sudo apt install -y bpftool
```

# wirefisher编译和运行

### 安装yaml-cpp

```
sudo apt install -y libyaml-cpp-dev
```

然后git:

```
git clone git@github.com:skaiui2/wirefisher.git
```

## 编译与运行

编译 BPF 程序：

```bash
cd bpf
make
cd ..
```

构建用户态控制程序：

```bash
mkdir build
cd build
cmake ..
make
```

启动 wirefisher：

```bash
sudo ./wirefisher
```

程序将根据 `config.yaml` 中的默认配置自动加载限速规则并开始运行，我们使用ctrl c即可中断wirefisher运行。

如果我们要更改限速规则：

然后进入配置目录：

```bash
cd config
vim config.yaml
```

可以这样配置：

```
process_module:
  process_rule:
    target_pid: 4580
    rate_bps: 1M
    gress: ingress
    time_scale: 1s
```

不需要再次编译，可以直接运行：

```
sudo ./wirefisher
```

现在wirefisher会根据更改的配置文件运行限速规则。
