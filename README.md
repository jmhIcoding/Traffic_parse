# 项目介绍
做流量分类，需要提取网络流量的原始特征。这里的原始特征包括：包长、包到达时间间隔、特殊头部字段、载荷。。。等等。
pyshark，scapy等python包解析库太特么难用了。难用主要体现在，对于标注的传输层协议UDP/TCP,它的属性字段是变化的。举个例子UDP上面的NetBIOS,pyshark和scapy就不能通过访问udp.payload得到，真是自作聪明。所以，还是自己写代码提取所需要的特征吧。
再多吐槽几句：**pyshark,scapy就是垃圾！！！！**
# 项目地址：
https://github.com/jmhIcoding/Traffic_parse

# 项目代码：
项目代码在：https://github.com/jmhIcoding/Traffic_parse/tree/master/src
VS工程目录在：https://github.com/jmhIcoding/Traffic_parse/tree/master/vsrc，可以直接用vs2013导入、然后重新构建。

需要提取啥特征在 https://github.com/jmhIcoding/Traffic_parse/blob/master/src/util.cpp里面，
里面有个DbgPrint函数：

```cpp
void DbgPrint(int level, void *header)
{
	ethII_header* eth_headerp = (ethII_header*)header;
	ip_header* ip_headerp = (ip_header*)header;
	udp_header* udp_headerp = (udp_header*)header;
	tcp_header* tcp_headerp = (tcp_header*)header;
	in_addr srcip, dstip;
	char srcip_dot[32] = { 0 }, dstip_dot[32] = { 0 };
	if(!(level & DEBUG_INFO))
	{
		return;
	}
	switch (level & DEBUG_INFO)
	{
	case eth_info:
		
		printf("EthII");
		for (int i = 0; i < sizeof(eth_headerp->destination); i++)
		{
			if (i == 0) printf("\tdst:");
			printf("%0.2X", eth_headerp->destination[i]);
			if (i < (sizeof(eth_headerp->destination) - 1)) printf(":");
		}
		for (int i = 0; i < sizeof(eth_headerp->source); i++)
		{
			if (i == 0) printf("\tsrc:");
			printf("%0.2X", eth_headerp->source[i]);
			if (i < (sizeof(eth_headerp->source) - 1)) printf(":");
		}
		printf("\ttype:%0.4X\n", eth_headerp->type);
		break;
	case tcp_info:
		printf("%d,%d,tcp,", tcp_headerp->sport, tcp_headerp->dport);
		break;
	case udp_info:
		printf("%d,%d,udp,", udp_headerp->sport, udp_headerp->dport);
		break;
	case ip_info:
		//printf("IP");
		srcip.S_un.S_addr = ip_headerp->saddr;
		dstip.S_un.S_addr = ip_headerp->daddr;
		//sprintf(srcip_dot, "%s", inet_ntoa(srcip));
		//sprintf(dstip_dot, "%s", inet_ntoa(dstip));
		//dont parse ip addr to xx.yy.zz.aa
		printf("%x,%x,", srcip.S_un.S_addr, dstip.S_un.S_addr);
		break;
	default:
		break;
	}
}
```
直接在这里修改，需要再各自的层输出什么样的信息。
需要解析哪一层是通过控制util.h文件的`DEBUG_INFO`这个宏来做到。

```cpp
#define eth_info	0x01
#define ip_info		0x02
#define tcp_info	0x04
#define udp_info	0x08
#define dns_info	0x10
#define http_info	0x20
#define https_info	0x40
#define raw_packet_info 0x80
//#define DEBUG_INFO (eth_info | ip_info | tcp_info | udp_info | dns_info | http_info | https_info)

#define DEBUG_INFO (ip_info|tcp_info|udp_info)
```
需要什么功能自己扩展吧。
