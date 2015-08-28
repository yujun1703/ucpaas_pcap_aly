// pcap_parser.cpp : Defines the entry point for the console application.
//

#include "pcap.h"
#include "stdio.h"
#include "malloc.h"
#include "string.h"

#define MAX_ETH_FRAME 1514
#define MAC_HEADER_LEN 14


int main()
{
	pcap_file_header  pfh;
	pcap_header  ph;
	int count = 0;
	unsigned char * buff = NULL;
	unsigned int readSize = 0;
	int ret = 0;

	buff = (unsigned char *)malloc(MAX_ETH_FRAME);
	FILE *fp = fopen("./test", "rb");

	if (fp == NULL) {
		fprintf(stderr, "Open file error.\n");
		return 0;
	}

	int headerlen = sizeof(pcap_file_header);

	//read pcap_file_header
	fread(&pfh, sizeof(pcap_file_header), 1, fp);

	prinfPcapFileHeader(&pfh);

	unsigned int sec_timestamp = 0;
	unsigned int m_timestamp = 0;
	unsigned int sleep_timestamp = 0;
	unsigned int sleep_timestamp_sec = 0;
	for (count = 1;; count++) {
		memset(buff, 0, MAX_ETH_FRAME);

		//read pcap header to get a packet
		//get only a pcap head count .
		readSize = fread(&ph, sizeof(pcap_header), 1, fp);
		if (readSize <= 0) {
			break;
		}

		printfPcapHeader(&ph);

		if (buff == NULL) {
			fprintf(stderr, "malloc memory failed.\n");
			return 0;
		}

		//read pcap body
		readSize = fread(buff, 1, ph.capture_len, fp);

		if (readSize != ph.capture_len) {
			free(buff);
			buff = NULL;
			fprintf(stderr, "pcap file parse error.\n");
			return 0;
		}

		int local = 0;
		int mediatype = 1;//1:video;0:audio
		//const char* dstaddr = "113.31.89.144";
		//const char* srcaddr = "172.16.2.113";

		//parse ip header,escape mac header
		int media = ipparse(buff + MAC_HEADER_LEN);
		if (readSize < 200)
		{
			mediatype = 0;
		}

		printf("===count:%d,readSize:%d===\n", count, readSize);
		if (feof(fp) || readSize <= 0) {
			break;
		}
	}

	if (buff) {
		free(buff);
		buff = NULL;
	}
	if (fp) {
		fclose(fp);
		fp = NULL;
	}
	return 0;
}

/*
int parse_pcap(FILE* fp,unsigned char* buff)
{
		pcap_header  ph;
		int readSize = 0;
		memset(buff, 0, MAX_ETH_FRAME);

		//read pcap header to get a packet
		//get only a pcap head count .
		readSize = fread(&ph, sizeof(pcap_header), 1, fp);
		if (readSize <= 0) {
			break;
		}

		printfPcapHeader(&ph);

		if (buff == NULL) {
			fprintf(stderr, "malloc memory failed.\n");
			return 0;
		}

		//read pcap body
		readSize = fread(buff, 1, ph.capture_len, fp);

		if (readSize != ph.capture_len) {
			free(buff);
			buff = NULL;
			fprintf(stderr, "pcap file parse error.\n");
			return 0;
		}

		int local = 0;
		int mediatype = 1;//1:video;0:audio
		char* dstaddr = "113.31.89.144";
		char* srcaddr = "172.16.2.113";

		//parse ip header,escape mac header
		int media = ipparse(buff + MAC_HEADER_LEN);
		if (readSize < 200)
		{
			mediatype = 0;
		}

		printf("===count:%d,readSize:%d===\n", count, readSize);
		if (feof(fp) || readSize <= 0) {
			break;
		}
	}
*/
