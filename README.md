# wirefisher
**wirefisher** is an eBPF-powered traffic control tool that enables precise rate limiting based on process ID, IP address, port, network interface, and cgroup. It is designed for lightweight, programmable traffic shaping in Linux environments.

**wirefisher** provides three major capabilities: real‑time network monitoring, fine‑grained traffic limiting, and adaptive performance tuning.

## Notice

I'm developing FlyFish, the distributed frontend for Wirefisher—if you have any suggestions or feature requests for Wirefisher, feel free to open an issue.

## Features

- Per-process bandwidth control
- IP, port, and protocol-based filtering
- Interface-level rate limiting
- Cgroup-based traffic shaping
- Ingress and egress direction support
- Real-time rate metrics: average, peak, and smoothed
- It monitors specific IP/port combinations and automatically switches the congestion control algorithm that you set in rule when a match is detected.

## Environment Setup

Two ways:

- [Command-line ](docs/中文/eBPF环境搭建.md)

or:

- [Docker ](docs/中文/docker.md)

## Configuration Example

Enter the documents:
```
$: cd config
/config: vim config.yaml
```

like this:

```yaml
process_module:
  process_rule:
    target_pid: 4580
    rate_bps: 1M
    gress: ingress
    time_scale: 1s
```

Other modules (cgroup, interface, IP/port/protocol) are available and can be enabled by uncommenting their sections in `config.yaml`.

## make

```bash
$: cd bpf
/bpf$: make
/bpf$: cd ..
$: mkdir build
$: cd build
/build$: cmake ..
/build$: make
/build$: sudo ./wirefisher
```

Now it will run!

## Requirements

- Linux kernel 5.4 or higher
- Root privileges
- libbpf and clang toolchain

