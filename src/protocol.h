#ifndef _APCAP_PROCOTOL_H
#define _APCAP_PROCOTOL_H
#include <pcap-stdinc.h>
#include <vector>
using namespace std;

/* 14 bytes Eth II header */
typedef struct ethII_header
{
	u_char destination[6];  //Ŀ��mac
	u_char source[6];		//Դmac
	u_short type;			//�ϲ������Э������
};
/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	u_long  saddr;      // Source address
	u_long  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
	
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

/*TCP header*/
typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	u_int sequence;
	u_int acknum;
	u_char tcpHeader_reserve;
	u_char flag;
	u_short window_size;
	u_short crc;
	u_short agency_point;
	u_int choice;
	u_char *appendix;
};

/*ע��:����ͷ���Ķ��岢����RFC�ı�׼����,ֻ��Ϊ�˷�����Զ�������ݽṹ*/

/* DNS header*/
typedef struct dns_query
{
	u_char * name;	//	��ѯ��
	u_short type;	//����
	u_short classes;
};
typedef struct dns_res
{
	u_char * name;//��ѯ��
	u_short type;
	u_short classes;
	u_long ttl;
	u_short dlen;//
	u_char* data;
};
typedef struct dns_header
{
	u_short transactionid;
	u_short flags;
	u_short question_number;	// the query numbers
	u_short answerrrs;	// �ش���Դ��Ŀ
	u_short authoriyrrs;
	u_short additionalrrs;
	dns_query *querys;
	dns_res *res;
};
typedef struct http_header
{
	char * URL;				//request url.
	char * UA;				//User-agent
	char * Host;			//Host field
	char * ContentType;		//ContentTypde
};

struct certificate
{
	char *subj;
	char *issuer;
	char *not_before;
	char *not_after;
};

typedef struct https_header
{
	u_char content_type;		// recoder���¼���ϲ�Э������ 22:����
	u_short *cipher_suites;		//
	u_short cipher_suites_items;//����
	char * sever_name;			//	extension server name
	vector< certificate > certs;		//֤��ṹ
};
typedef struct tcp_packet_inner	//���������
{
	u_int	sequence;//��tcp����sequence
	u_int length;	 //��tcp����length
	u_int offset;	 //��tcp�����غ�����Ӧ�����ְ�
};
typedef struct https_handshark_inner
{
	u_int sip,dip;
	u_short sport,dport;
	u_int length;
	u_int alloc_length;
	unsigned char * data;
	vector<tcp_packet_inner>  tcp_order_trace ;//tcp ������
};
#endif