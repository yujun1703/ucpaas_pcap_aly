//
//  pcap.c
#include "pcap.h"
#include <stdio.h>
#include <arpa/inet.h>
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
//逐位解析IP头中的信息
void getVersion(BYTE b, BYTE & version)
{
	version = b >> 4;         //右移4位,获取版本字段        
}

void getIHL(BYTE b, BYTE & result)
{
	result = (b & 0x0f) * 4;    //获取头部长度字段
}

const char * parseServiceType_getProcedence(BYTE b)
{
	switch (b >> 5)          //获取服务类型字段中优先级子域
	{
	case 7:
		return "Network Control";
		break;
	case 6:
		return "Internet work Control";
		break;
	case 5:
		return "CRITIC/ECP";
		break;
	case 4:
		return "Flash Override";
		break;
	case 3:
		return "Flsah";
		break;
	case 2:
		return "Immediate";
		break;
	case 1:
		return "Priority";
		break;
	case 0:
		return "Routine";
		break;
	default:
		return "Unknow";
		break;
	}
}

const char * parseServiceType_getTOS(BYTE b)
{
	b = (b >> 1) & 0x0f;        //获取服务类型字段中的TOS子域
	switch (b)
	{
	case 0:
		return "Normal service";
		break;
	case 1:
		return "Minimize monetary cost";
		break;
	case 2:
		return "Maximize reliability";
		break;
	case 4:
		return "Maximize throughput";
		break;
	case 8:
		return "Minimize delay";
		break;
	case 15:
		return "Maximize security";
		break;
	default:
		return "Unknow";
	}
}

void getFlags(WORD w, BYTE & DF, BYTE & MF)      //解析标志字段
{
	DF = (w >> 14) & 0x01;
	MF = (w >> 13) & 0x01;
}

void getFragOff(WORD w, WORD & fragOff)         //获取分段偏移字段 
{
	fragOff = w & 0x1fff;
}

const char * getProtocol(BYTE Protocol)             //获取协议字段共8位
{
	switch (Protocol)                          //以下为协议号说明：
	{
	case 1:
		return "ICMP";
	case 2:
		return "IGMP";
	case 4:
		return "IP in IP";
	case 6:
		return "TCP";
	case 8:
		return "EGP";
	case 17:
		return "UDP";
	case 41:
		return "IPv6";
	case 46:
		return "RSVP";
	case 89:
		return "OSPF";
	default:
		return "UNKNOW";
	}
}

int ipparse(unsigned  char* buffer)
{

	printf("data:");
	for (int i = 0; i < 16; i++)
	{
		printf("0x%x ", buffer[i]);
	}
	printf("\n\n");

	IP_HEADER ip = *(IP_HEADER*)buffer;       //通过指针把缓冲区的内容强制转化为IP_HEADER数据结构
	BYTE version;
	getVersion(ip.Version, version);
	printf( "版本号=%d\r\n", version);
	BYTE headerLen;
	getIHL(ip.HdrLen, headerLen);
	printf( "报头标长=%d(BYTE)\r\n", headerLen);
	printf( "服务类型=%s,%s\r\n",
	parseServiceType_getProcedence(ip.ServiceType),
	parseServiceType_getTOS(ip.ServiceType));
	printf( "总长度=%d(BYTE)\r\n", ip.TotalLen);
	printf( "标识=%d\r\n", ip.ID);
	BYTE DF, MF;
	getFlags(ip.Flags, DF, MF);
	printf( "标志 DF=%d,MF=%d\r\n", DF, MF);
	WORD fragOff;
	getFragOff(ip.FragOff, fragOff);
	printf( "分段偏移值=%d\r\n", fragOff);
	printf( "生存期=%d（hopes)\r\n", ip.TimeToLive);
	printf( "协议=%s\r\n", getProtocol(ip.Protocol));
	printf( "头校验和=0x%0x\r\n", ip.HdrChksum);
	printf( "源IP地址=%s\r\n", inet_ntoa(*(in_addr*)&ip.SrcAddr));
	printf( "目的IP地址=%s\r\n", inet_ntoa(*(in_addr*)&ip.DstAddr));

	printf("源端口=%d\r\n", htons(ip.SrcPort));
	printf("目的端口=%d\r\n", htons(ip.DstPort));
	printf( "---------------------------------------------\r\n");

	if (ip.Protocol == UDP)
	{
		
	}
	return 0;
}

void prinfPcapFileHeader(pcap_file_header *pfh){
	if (pfh==NULL) {
		return;
	}
	printf("=====================\n"
		   "magic:0x%0x\n"
		   "version_major:%u\n"
		   "version_minor:%u\n"
		   "thiszone:%d\n"
		   "sigfigs:%u\n"
		   "snaplen:%u\n"
		   "linktype:%u\n"
		   "=====================\n",
		   pfh->magic,
		   pfh->version_major,
		   pfh->version_minor,
		   pfh->thiszone,
		   pfh->sigfigs,
		   pfh->snaplen,
		   pfh->linktype);
}
 
void printfPcapHeader(pcap_header *ph){
	if (ph==NULL) {
		return;
	}
	printf("=====================\n"
		   "ts.timestamp_s:%u\n"
		   "ts.timestamp_ms:%u\n"
		   "capture_len:%u\n"
		   "len:%d\n"
		   "=====================\n",
		   ph->ts.timestamp_s,
		   ph->ts.timestamp_ms,
		   ph->capture_len,
		   ph->len);
}
 
