FROM ubuntu:25.04

ENV DEBIAN_FRONTEND=noninteractive

# 更新并安装 eBPF + 编译工具链 + Kafka + yaml-cpp + JSON 库
RUN apt-get update && apt-get install -y \
    clang llvm \
    libelf-dev libbpf-dev \
    bpftool bpfcc-tools \
    build-essential git cmake pkg-config \
    linux-tools-common linux-tools-generic \
    linux-headers-generic \
    librdkafka-dev \
    libyaml-cpp-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN rm -rf build && mkdir build && cd build && cmake .. && make -j$(nproc)

CMD ["/bin/bash"]

