# TODO
## 速率控制 && 重传检测
参考nmap与masscan

## libpcap 依赖

引用nmap中集成的libpcap，linux与osx下都能正常编译执行
直接git clone libpcap，然后checkout到1.73版本
linux上编译运行后会提示undefined symbol: dbus_bus_get
osx下正常


# 安装
## libpcap
```
git submodule init && git submodule update &&npm run build
```

## node-creeper
```
node-gyp build --debug

DirtyBox:node-creeper cboy$ sudo node ./
[0x7fff760cf000]  thread Main
filter exp: src host 13.229.188.59
 [0x700002812000]  thread PiWorker
[0x7fff760cf000]  thread Capture::process
TCP port 22 open , possible service: ???
[0x7fff760cf000]  thread Capture::process
TCP port 80 open , possible service: ???
[0x7fff760cf000]  thread Capture::process
TCP port 443 open , possible service: ???```

```


# 修改

讲原版的阻塞＋callback实现
替换为获取pcap session的socket description，添加到uv_poll中，等待网络事件触发回调

# 实现差异

## IP_HDRINCL

socket handler上存在差异
RAW socket可以衔接到所有IP协议的处理程序上。
内核&RAW socket会收到相同的数据包。（BSD与Linux存在一定差异）。

包收发上，会头部进行的操作存在差异
不会对协议投做出任何修改（设置了IPHDRINCL选项除外）。
不同的raw socket对头部的修改，在行为上存在差异。


###linux

Raw socket 会自动为通过该socket发送的数据添加IP头信息
设置该选项，达到自定义IP头的目的。如果只是处理接收，这个选项设置不设置都无所谓。

设置该选项之后，会自动填充以下字段：

* IP Checksum
* Source Address
* Packet ID
* Total Length

Linux 2.2内核之后，所有的ip字段均可通过socket options接口进行设置。
Raw socket的接收优先级要高于内核的protocol handler


收发处理

收发接口，使用sockaddr_in结构来获取地址信息
发送时，端口字段sin_port必须设置为0
接收时，端口字段sin_port自动设置为0


MTU与分片

内核会持续侦测MTU大小，EMSGSIZE错误。
关闭MTU自动发现（/proc/sys/net/ipv4/ip_no_pmtu_disc）

```
[root@la-lg ~]# cat /proc/sys/net/ipv4/ip_no_pmtu_disc
0

```
关闭该选项，能达到让内核自动处理分片的功能（性能和可靠性没保证）。


Raw Socket可通过bind接口，绑定到特定的地址。
也可通过SO_BINDTODEVICE参数，绑定到特定的接口。

IPPROTO_RAW类型的socket一般只做发送使用。
如果希望接收所有的IP包，建议使用AF_PACKET类型的socket，并制定ETH_P_IP协议类型。该类型的socket不会进行IP分片重组。


接收处理ICMP包，只需要用户级的socket，通过IP_RECVERR就可以处理。


### BSD




# BUG

原版实现中，使用pcap便利网络设备地址，默认选择第一个ip地址的逻辑，在linux上适用。
在OSX上首个地址为0.0.0.0，用该地址计算出的tcp层的checksum，会导致丢包。
ip层的checksum由内核获取到正确地址之后，计算得出，不存在问题。



# Remark
 
fedora 28 以及 OSX 10.11.6 上测试过
理论上debain系和红帽系列的系统也可以直接使用

不支持windows！！！


# References
[IP_HDRINCTL in linux ]([linux](http://man7.org/linux/man-pages/man7/raw.7.html))

[bsd上的raw socket使用](http://www.enderunix.org/docs/en/rawipspoof/)

[linux & bsd 下 raw socket的差异](https://sock-raw.org/papers/sock_raw)

[原版实现](https://sock-raw.org/papers/syn_scanner)