// pcap_parser.cpp : Defines the entry point for the console application.
//

#include "pcap.h"
#include "stdio.h"
#include "malloc.h"


#define MAX_ETH_FRAME 1514
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
	for (count = 1;; count++) 
	{
		if(parse_pcap( fp, buff)<0)
			break;
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

