#include <util.h>
#ifdef DEBUG_INFO
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


void display(unsigned char * pkt_data, int len, int nextline)
{
	if (!(DEBUG_INFO & raw_packet_info))
		//û�д򿪴�ӡ���ĵ�ѡ��
	{
		return;
	}
	for (int i = 0; i < len;)
	{
		printf("%.2X ", pkt_data[i]);
		i += 1;
		if (i % nextline == 0)
		{
			printf("\n");
		}
	}
	printf("\n");
}
#else
#define DEBUG_INFO (0)
#define DbgPrint(int,const char *,...)     ;
#define display(unsigned char *,int,int)   ;
#endif
pcap_gather::pcap_gather(char *pcapfilename)
{
	this->pcapt = pcap_open_offline(pcapfilename, this->errBuf);
	if (this->pcapt == NULL)
	{
		printf("Error when open pcap file. error is :%s\n",this->errBuf);
		//system("pause");
		//exit(-1);
	}
}

void pcap_gather::set_filter(char *FilterString, pcap_t * pt)
//���ù�����
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	bpf_program *fprog = new bpf_program();

	if (pcap_compile(pt, fprog, FilterString, 1, 0) == -1)
	{
		printf("compile filter error.\n");
	}

	if (pcap_setfilter(pt, fprog) == -1)
	{
		printf("set filter error.\n");
	}
}

vector< _packet> pcap_gather::get_packets(pcap_t * pt)
//��ȡȫ������,��Ҫ����ͨ���ļ���ȡ����
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	vector< _packet> rst;
	while (true)
	{
		_packet pkt;
		get_next_packet(&pkt);
		if (pkt.data)
		{
			rst.push_back(pkt);
		}
		else
		{
			break;
		}
	}
	return rst;
}
void pcap_gather::get_next_packet(_packet * packet, pcap_t * pt)
//һ��һ���Ļ�ȡ����
{
	if (pt == NULL)
	{
		pt = this->pcapt;
	}
	pcap_pkthdr pktheader;
	const u_char *pktdata = pcap_next(pt, &pktheader);
	if (pktdata != NULL)
	{
		packet->len = pktheader.caplen;
		packet->timestamp = pktheader.ts.tv_sec;
		packet->usec = pktheader.ts.tv_usec;
		packet->data = (u_char *)pktdata;// do not free 
	}
}

ethII_header eth_parser(unsigned char * pkt_data)
//��̫���Ľ���,����һ����̫����header
{
	ethII_header header = { 0 };
	ethII_header * data = (ethII_header*)pkt_data;
	memcpy(&header, data, sizeof(ethII_header));
	header.type = ntohs(header.type);
	DbgPrint(eth_info, &header);
	return header;
}
ip_header ip_parser(unsigned char *  ip_data)
//ip���ĵĽ���
{
	ip_header header = { 0 };
	ip_header * data = (ip_header*)ip_data;
	memcpy(&header, data, sizeof(ip_header));
	header.tlen = ntohs(header.tlen);
	header.identification = ntohs(header.identification);
	header.flags_fo = ntohs(header.flags_fo);
	header.crc = ntohs(header.crc);
	//header.saddr = ntohl(header.saddr);
	//header.daddr = ntohl(header.daddr);
	//DbgPrint(ip_info, &header);
	return header;
}


udp_header udp_parser(unsigned char * udp_data)
//udp���ĵĽ���
{
	udp_header header = { 0 };
	udp_header * data = (udp_header *)udp_data;
	memcpy(&header, data, sizeof(udp_header));
	header.sport = ntohs(header.sport);
	header.dport = ntohs(header.dport);
	header.len = ntohs(header.len);
	header.crc = ntohs(header.crc);
	//DbgPrint(udp_info, &header);
	return header;
}

tcp_header tcp_parser(unsigned char * tcp_data)
//tcp���ĵĽ���
{
	tcp_header header = { 0 };
	tcp_header * data = (tcp_header*)tcp_data;
	memcpy(&header, data, sizeof(tcp_header));
	header.sport = ntohs(header.sport);
	header.dport = ntohs(header.dport);
	header.sequence = ntohl(header.sequence);
	header.acknum = ntohl(header.acknum);
	header.crc = ntohs(header.crc);
	//DbgPrint(tcp_info, &header);
	return header;
}