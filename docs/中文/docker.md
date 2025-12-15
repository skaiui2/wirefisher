## 环境

ubuntu22.04虚拟机。

内核版本6.8

## 一些必要的工具

虚拟机安装应该不用说了。

还有一个很重要的东西：代理（科学上网）。

本文docker的拉取会受到墙的影响，当然，这里是GitHub，对各位来说应该没什么问题。

## docker安装

```
sudo apt update
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

然后验证：

```
docker --version
```

### 拉取镜像

```
sudo docker pull skaiuijing/wirefisher-ebpf:latest
```

如果拉取成功，跳到运行那里。

### 拉取不成功

这个时候你需要代理。

笔者使用的代理是v2rayn，在设置的参数设置里面，把：允许来自局域网的连接和为新的局域网开启端口两个选项勾选上。

然后在Ubuntu的settings里面，把Network proxy改成手动，然后填写上你主机上网的ip还有v2rayn的局域网端口。

不过我们需要让docker也走代理：

执行下面的命令：

```
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo vim /etc/systemd/system/docker.service.d/http-proxy.conf
```

把下面的信息写进去：

记得把下面的ip和端口改了。

```
[Service]
Environment="HTTP_PROXY=http://你主机上网的ip:局域网端口"
Environment="HTTPS_PROXY=http://你主机上网的ip:局域网端口"
Environment="NO_PROXY=localhost,127.0.0.1"
```

然后重启：

```
sudo systemctl daemon-reexec
sudo systemctl restart docker
```

重新拉取：

```
sudo docker pull skaiuijing/wirefisher-ebpf:latest
```

## 运行

确保我们允许前有一定的权限：

```
sudo docker run -it --rm \
  --privileged \
  --cap-add=SYS_ADMIN \
  --cap-add=NET_ADMIN \
  --cap-add=IPC_LOCK \
  skaiuijing/wirefisher-ebpf
```

然后手动设置 RLIMIT_MEMLOCK，用ulimit提升：

```
ulimit -l unlimited
```

最后，确保自己在build文件夹：

```
./wirefisher
```

如果出现下面的信息，说明成功了：

```
root@b9f898de050f:/app/build# ./wirefisher 
跳过模块：tc_process（未配置）
加载模块：tc_port
=== ip_pro_port_rule ===
 target_ip         : 192.168.91.131
 target_port       : 9090
 target_protocol   : 6
 rate_bps          : 5242880 bps
 time_scale        : 1 sec
 gress             : ingress
 ip_enable         : false
 port_enable       : false
 protocol_enable   : false
========================
[netfilter] 成功附加 netfilter 钩子
[netfilter] 模块加载完成，开始处理事件
跳过模块：tc_eth（未配置）
跳过模块：tc_cgroup（未配置）
=== ip pro port traffic ===
 src_ip     : 10.149.115.87
 dst_ip     : 172.17.0.2
 src_port   : 33827
 dst_port   : 21153
 protocol   : TCP
```

当然，你可能会发现一些报错信息，这无伤大雅：

这些信息来自kafka，它表示自己无法连接到 Broker。

```
3|1765812788.348|ERROR|rdkafka#producer-1| [thrd:app]: rdkafka#producer-1: 10.149.115.87:9092/bootstrap: Connect to ipv4#10.149.115.87:9092 failed: Connection refused (after 21041ms in state CONNECT, 1 identical error(s) suppressed)
```

你可以安装并启动broker，然后可以在config文件夹的config.yaml文件里面更改你的消费者ip及端口号，这样就能在其他平台接收到json形式的数据了。

笔者之前的设计计划是分布式监控，所以使用kafka作为消息队列，如果你在主机上配置好对应的消费者，就能接收到wirefisher推送的数据，你可以存储这些数据，并把这些数据推送给web前端。

之前写的项目flyfish和fisher就是干这些事情的，不过笔者只是简单写了一下，跑通了整个流程，等过段时间有空再把wirefisher的前端写完，当然，你也可以尝试自己写，因为笔者可能很久很久都不会写。

## 测试

写个python脚本测试一下：

这里的ip就是docker的网卡ip了，我们可以通过ifconfig等命令查看ip，这个docker比较简陋，ifconfig都没有，所以读者可能还需要安装一下这些工具。

```python
import socket

target_ip = "172.17.0.2"
target_port = 9999
data = b"A" * 1024  # 每个报文 1KB

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(100000):  # 循环发送
    sock.sendto(data, (target_ip, target_port))
```

接着运行这个测试脚本：

```python
python3 send.py
```

wirefisher很快就做出了反应：

```
=====================
=== ip pro port traffic ===
 src_ip     : 172.17.0.1
 dst_ip     : 172.17.0.2
 src_port   : 59060
 dst_port   : 3879
 protocol   : UDP
 instant_rate_bps : 3.14 MB/s
 rate_bps         : 3.14 MB/s
 peak_rate_bps    : 10.28 MB/s
 smoothed_rate_bps: 1.29 MB/s
 timestamp         : 00:46:58.951
=====================
=== ip pro port traffic ===
 src_ip     : 172.17.0.1
 dst_ip     : 172.17.0.2
 src_port   : 59060
 dst_port   : 3879
 protocol   : UDP
 instant_rate_bps : 3.14 MB/s
 rate_bps         : 3.14 MB/s
 peak_rate_bps    : 10.28 MB/s
 smoothed_rate_bps: 1.29 MB/s
 timestamp         : 00:46:58.951
=====================
=== ip pro port traffic ===
 src_ip     : 172.17.0.1
 dst_ip     : 172.17.0.2
 src_port   : 59060
 dst_port   : 3879
 protocol   : UDP
 instant_rate_bps : 3.14 MB/s
 rate_bps         : 3.14 MB/s
 peak_rate_bps    : 10.28 MB/s
 smoothed_rate_bps: 1.29 MB/s
 timestamp         : 00:46:58.951
```



## 结语

好了，大功告成，尽情玩耍吧。







