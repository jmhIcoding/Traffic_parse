//ͷ�ļ�,���ڶ�winpcap����ĺ������з�װ
#ifndef UTIL_H_INCLUDED
	#define UTIL_H_INCLUDED
#ifndef WPCAP
#define	WPCAP
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap-stdinc.h>
#include <pcap.h>
#include <protocol.h>
#include <vector>
#include <set>
#include <map>
#include <string.h>
#pragma pack(1)


using namespace std;

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
ethII_header  eth_parser(unsigned char * pkt_data);//��̫���Ľ���
ip_header ip_parser(unsigned char *  ip_data);//ip���ĵĽ��� ,
tcp_header tcp_parser(unsigned char * tcp_data);//tcp���ĵĽ���
udp_header udp_parser(unsigned char * udp_data);//udp���ĵĽ���
void display(unsigned char * pkt_data, int len, int nextline = 16);//�����ݴ�ӡ
void DbgPrint(int level, void *header);
struct _packet
{
	int len;
	long int timestamp;//second
	long int usec;//u second .
	unsigned char * data;
	_packet() :len(0), timestamp(0), data(0)
	{
		;
	}

};

class pcap_gather
{

public:
	pcap_gather(char * pcapfile);//���ļ��ж���
	pcap_gather(int interfaces);//��������ץȡʵʱ�ı���
	void set_filter(char *filter, pcap_t * pt = NULL);
	vector< _packet> get_packets(pcap_t * pt = NULL);//��ȡȫ������,��Ҫ����ͨ���ļ���ȡ����
	void get_next_packet(_packet * packet, pcap_t * pt = NULL);//һ��һ���Ļ�ȡ����
	~pcap_gather()
	{
		if (pcapt)
		{
			pcap_close(pcapt);
		}
	}
public:
	pcap_t * pcapt;
	char errBuf[2048];
};

#endif // UTIL_H_INCLUDED
