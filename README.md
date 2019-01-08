# 代码结构

## 设备枚举

默认pcap会话所关联的默认接口的获取

可通过获取路由表中的默认路由表项管理的接口来实现，
但是linux，unix，windows下的路由表实现以及表项中所携带的信息均不相同。
参考nmap中的关于默认路由的获取，找到一个名为[libdnet](http://libdnet.sourceforge.net/) 的项目，其中包含一个route.h的接口抽象，可实现以统一放方式，获取默认路由信息，从而获取到默认接口


```
# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.250.254 0.0.0.0         UG    0      0        0 fd7196069ef7d2e
10.211.55.0     0.0.0.0         255.255.255.0   U     0      0        0 enp0s5
```


```
$ netstat -rn -f inet
Routing tables

Internet:
Destination        Gateway            Flags        Refs      Use   Netif Expire
default            192.168.25.1       UGSc          195        0     en0
```


```
C:\Users\Administrator>route print -4
===========================================================================
Interface List
 13...00 ff cd da af 2f ......Sangfor SSL VPN CS Support System VNIC
 18...02 00 4c 4f 4f 50 ......Npcap Loopback Adapter
 17...00 ff a3 32 44 81 ......TAP-Win32 Adapter V9 #3
 15...00 ff e1 23 f3 8d ......TAP-Win32 Adapter V9 #2
 14...00 ff bc 1e 73 21 ......TAP-Win32 Adapter V9
 11...00 c1 42 11 2a 6a ......Intel(R) PRO/1000 MT Network Connection
  1...........................Software Loopback Interface 1
 21...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
 12...00 00 00 00 00 00 00 e0 Teredo Tunneling Pseudo-Interface
 20...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #2
 16...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #3
 19...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #4
 22...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #5
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.25.1    192.168.25.92    266
```
## 端口扫描

scanner对象

* 域名解析 -> IP
* 周期性的向nodejs工作线程提交TCP包发送请求 （rate control）


packet对象

* IPPacket

```
class IPPacket{
public:
        IPPacket();
        ~IPPacket();


        //返回偏移量
        virtual char *build(const char *sip, const char *dip, int dport, int sport = 9876);
        uint16_t checksum (uint16_t *addr, int len);


        char _buffer[4096];
};
```
* TCPPacket

```
class TCPPacket : public IPPacket{
public:
        TCPPacket();
        ~TCPPacket();


        virtual char *build(const char *sip, const char *dip, int dport, int sport = 9876);

        u_short tcpChecksum();
};

```
* ApplicationPacket

```
ApplicationPacket::build()
{
	IPPacket::build();
	TCPPacket::build();

	//Add you custom packet generate code here

}
```




capture对象

* 完成pcap会话创建
* 将pcap会话中所绑定fd关联到libuv中，执行时间监听
* 在libuv的回调中，完成包解析，提取来自目标服务器的端口响应



每次扫描，pcap会话所绑定的filter均不相同，因此，每个scanner对象只能对应一个扫描。
