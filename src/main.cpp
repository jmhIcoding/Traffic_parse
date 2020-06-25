#include <util.h>
#include <time.h>
#include "BaseTool.h"
#define PCAPDIR "C:\\Users\\jmh081701\\Documents\\i-know-what-are-you-doing\\pcap\\micrords\\editing_doc\\"
void print_payload(unsigned char *data, int len)
{
	for (int i = 0; i < len; i++)
	{
		printf("%0.2x", data[i]);
		if (i < (len - 1))
		{
			printf(" ");
		}
	}
}
int clean_pcap(char *pcapname, char * filter = "host 47.100.21.91 and(tcp or udp)",char redirect=1)
{
	pcap_gather gather = pcap_gather(pcapname);
	if (gather.pcapt == NULL)
	{
		return  -1;
	}
	if (filter != NULL)
		//set filter
	{
		gather.set_filter(filter);
	}
	if (redirect)
	{
		pcapname[strlen(pcapname) - 4] = 't';
		pcapname[strlen(pcapname) - 3] = 'x';
		pcapname[strlen(pcapname) - 2] = 't';
		pcapname[strlen(pcapname) - 1] = 0;
		freopen(pcapname, "w", stdout);
	}
	int packetno = 1;
	while (true)
	{
		_packet packet;
		gather.get_next_packet(&packet);
		if (!redirect)
		{
			printf("id:%d\t", packetno);
		}

		//if (packetno == 1203)
		//{
		//	__asm
		//	{
		//		int 0x3
		//	};

		//}
		if (packet.data && packet.len)
		{
			ethII_header eth = eth_parser(packet.data);

			if (eth.type == 0x0800)
				//ip Ð­Òé
			{
				
				ip_header ip = ip_parser(packet.data + sizeof(ethII_header));//parse ip header
				if (ip.proto == 0x11)
					//udp
				{
					udp_header udp = udp_parser(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF));//parse udp header
					if (udp.len - 8)
					{
						printf("%d.%d,", packet.timestamp, packet.usec);
						DbgPrint(ip_info, &ip);
						DbgPrint(udp_info, &udp);
						printf("%d,", udp.len - 8);
						//print_payload(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF) + 8, udp.len - 8);
						printf("\n");
					}
				}
				else if (ip.proto == 0x06)
					//tcp
				{
					tcp_header tcp = tcp_parser(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF));//parse tcp header
					int len = ip.tlen - 4 * (ip.ver_ihl & 0xF) - 4 * ((tcp.tcpHeader_reserve & 0xF0) >> 4);
					if (len>0 && len <= 1460)
					{
						printf("%d.%d,", packet.timestamp, packet.usec);
						DbgPrint(ip_info, &ip);
						DbgPrint(tcp_info, &tcp);
						printf("%d,", len);
						printf("\n");
					}
					else if (len > 1460)
					{
						int i;
						for (i = 0; i < (len / 1460); i++)
						{
							printf("%d.%d,", packet.timestamp, packet.usec);
							DbgPrint(ip_info, &ip);
							DbgPrint(tcp_info, &tcp);
							printf("%d,", 1460);
							printf("\n");
						}
						if (i * 1460 < len)
						{
							printf("%d.%d,", packet.timestamp, packet.usec);
							DbgPrint(ip_info, &ip);
							DbgPrint(tcp_info, &tcp);
							printf("%d,", len - i * 1460);
							printf("\n");
						}
					}
					else if (len<0)
						//need to frack.
					{
						int i;
						for (i = 0; i < (packet.len / 1460); i++)
						{
							printf("%d.%d,", packet.timestamp, packet.usec);
							DbgPrint(ip_info, &ip);
							DbgPrint(tcp_info, &tcp);
							printf("%d,", 1460);
							printf("\n");
						}
						if (i * 1460 < packet.len)
						{
							printf("%d.%d,", packet.timestamp, packet.usec);
							DbgPrint(ip_info, &ip);
							DbgPrint(tcp_info, &tcp);
							printf("%d,", packet.len-i*1460);
							printf("\n");
						}
					}
				}
				
			}
			packetno++;
		}
		else
		{
			//printf("Analyse Over...\n");
			break;
		}
	}
	if (redirect)
	{
		fclose(stdout);
	}
	return 0;
}
int main(int argc,char *argv[])
{
	//int start = clock();
	//char pcapname[] = "1556411102.pcap";
	//clean_pcap(pcapname, "host 47.100.21.91 and (tcp or udp)", 1);
	//int end = clock();
	//freopen("CON", "w", stdout);
	//printf("Time Use:%d\n", end - start);
	//return 0;

	if (argc != 3)
	{
		printf("[usage]:vsrcs.exe srcpcap_dir filter\n");
		exit(-1);
	}
	char PCAPDIR_[230] = { 0 };
	sprintf(PCAPDIR_, "%s\\*", argv[1]);
	vector<string> files = get_files_from_dir(PCAPDIR_,".pcap");
	PCAPDIR_[strlen(PCAPDIR_) - 1] = 0;
	for (int i = 0; i < files.size(); i++)
	{
		char pcapname[256] = { 0 };
		freopen("CON", "w", stdout);
		sprintf(pcapname, "%s%s", PCAPDIR_, files[i].c_str());
		printf("(%0.3f/100)\t%s\n",i*100.0/files.size(), pcapname);
		if (clean_pcap(pcapname, argv[2], 1) == -1)
		{
			printf("Error!!!!%s\n", files[i].c_str());
		}
	}
	//system("pause");
	return 0;
}