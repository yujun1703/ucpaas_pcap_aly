//
//  pcap.h

 
#ifndef pcaptest_pcap_h
#define pcaptest_pcap_h
 
typedef unsigned int  bpf_u_int32;
typedef unsigned short  u_short;
typedef int bpf_int32;
#define UDP 17



/*
pcap媒体流文件内部协议层次：
-pcap_file_header
-----pcap_header
-----mac header
-----_IP_HEADER
-----_RTP_HEADER
*/

/*
 Pcap文件头24B各字段说明：
 Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始
 Major：2B，0x02 00:当前文件主要的版本号     
 Minor：2B，0x04 00当前文件次要的版本号
 ThisZone：4B当地的标准时间；全零
 SigFigs：4B时间戳的精度；全零
 SnapLen：4B最大的存储长度    
 LinkType：4B链路类型
 常用类型：
 　0            BSD loopback devices, except for later OpenBSD
 1            Ethernet, and Linux loopback devices
 6            802.5 Token Ring
 7            ARCnet
 8            SLIP
 9            PPP
 */
typedef struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;    
	bpf_u_int32 sigfigs;   
	bpf_u_int32 snaplen;   
	bpf_u_int32 linktype;  
}pcap_file_header;
 
/*
 Packet 包头和Packet数据组成
 字段说明：
 Timestamp：时间戳高位，精确到seconds     
 Timestamp：时间戳低位，精确到microseconds
 Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
 Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
 Packet 数据：即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规定捕获的Packet数据包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。
 */
 
typedef struct  timestamp{
	bpf_u_int32 timestamp_s;
	bpf_u_int32 timestamp_ms;
}timestamp;
 
typedef struct pcap_header{
	timestamp ts;
	bpf_u_int32 capture_len;
	bpf_u_int32 len;
 
}pcap_header;


typedef struct _RTP_HEADER
{
	union
	{
		unsigned short V;
		unsigned short P;
		unsigned short X;
		unsigned short CC;
		unsigned short M;
		unsigned short PT;
	};

	unsigned short seq;
	unsigned int timestamp;
}RTP_HEADER;

#if 1
typedef struct _IP_HEADER  //定义IP头
{
	union
	{
		char Version;     //版本（前4位）
		char HdrLen;       //IHL（后4位），报头标长
	};
	char ServiceType;    //服务类型
	unsigned short TotalLen;       //总长
	unsigned short ID;             //标识
	union
	{
		unsigned short Flags;      //标志（前3位）
		unsigned short FragOff;    //分段偏移（后13位）
	};
	char TimeToLive;    //生命期
	char Protocol;      //协议
	unsigned short HdrChksum;     //头校验和    
	unsigned long SrcAddr;      //源地址
	unsigned long DstAddr;      //目的地址

	unsigned short SrcPort;      //源地址
	unsigned short DstPort;      //目的地址
	int Options;       //选项
}IP_HEADER;

#else
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;

typedef struct _IP_HEADER  //定义IP头
{
	union
	{
		BYTE Version;     //版本（前4位）
		BYTE HdrLen;       //IHL（后4位），报头标长
	};
	BYTE ServiceType;    //服务类型
	WORD TotalLen;       //总长
	WORD ID;             //标识
	union
	{
		WORD Flags;      //标志（前3位）
		WORD FragOff;    //分段偏移（后13位）
	};
	BYTE TimeToLive;    //生命期
	BYTE Protocol;      //协议
	WORD HdrChksum;     //头校验和    
	DWORD SrcAddr;      //源地址
	DWORD DstAddr;      //目的地址
	BYTE Options;       //选项
}IP_HEADER;

#endif
void prinfPcapFileHeader(pcap_file_header *pfh);
void printfPcapHeader(pcap_header *ph);
void printPcap(void * data,int size);
int ipparse(unsigned  char* buffer);
#endif
