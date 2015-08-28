//
//  main.c
//  pcaptest
//
//  Created by zc on 12-1-24.
//  Copyright 2012Äê __MyCompanyName__. All rights reserved.
//
 
#include <stdio.h>
#include <arpa/inet.h>
#include "pcap.h"
 
#define PCAP_FILE "ping.pcap"
#define MAX_ETH_FRAME 1514
#define ERROR_FILE_OPEN_FAILED -1
#define ERROR_MEM_ALLOC_FAILED -2
#define ERROR_PCAP_PARSE_FAILED -3
 
 
int main (int argc, const char * argv[])
{
 
	printf("sizeof:int %lu,unsigned int %lu,char %lu,unsigned char %lu,short:%lu,unsigned short:%lu\n",
		    sizeof(int),sizeof(unsigned int),sizeof(char),sizeof(unsigned char),sizeof(short),sizeof(unsigned short));
 
	pcap_file_header  pfh;
	pcap_header  ph;
	int count=0;
	void * buff = NULL;
	int readSize=0;
	int ret = 0;
 
	FILE *fp = fopen(PCAP_FILE, "rw");
 
	if (fp==NULL) {
		fprintf(stderr, "Open file %s error.",PCAP_FILE);
		ret = ERROR_FILE_OPEN_FAILED;
		goto ERROR;
	}
 
	fread(&pfh, sizeof(pcap_file_header), 1, fp);	
	prinfPcapFileHeader(&pfh);
	//fseek(fp, 0, sizeof(pcap_file_header));
 
	buff = (void *)malloc(MAX_ETH_FRAME);
	for (count=1; ; count++) {
		memset(buff,0,MAX_ETH_FRAME);
		//read pcap header to get a packet
		//get only a pcap head count .
		readSize=fread(&ph, sizeof(pcap_header), 1, fp);
		if (readSize<=0) {
			break;
		}
		printfPcapHeader(&ph);
 
 
		if (buff==NULL) {
			fprintf(stderr, "malloc memory failed.\n");
			ret = ERROR_MEM_ALLOC_FAILED;
			goto ERROR;
		}
 
		//get a packet contents.
		//read ph.capture_len bytes.
		readSize=fread(buff,1,ph.capture_len, fp);
		if (readSize != ph.capture_len) {
			free(buff);
			fprintf(stderr, "pcap file parse error.\n");
			ret = ERROR_PCAP_PARSE_FAILED;
			goto ERROR;
		}
		printPcap(buff, ph.capture_len);
 
 
		printf("===count:%d,readSize:%d===\n",count,readSize);
 
		if (feof(fp) || readSize <=0 ) { 
			break;
		}
	}
 
ERROR:
	//free
	if (buff) {
		free(buff);
		buff=NULL;
	} 
	if (fp) {
		fclose(fp);
		fp=NULL;
	}	
 
    return ret;
}