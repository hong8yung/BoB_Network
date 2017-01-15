
#include "pcap.h"
#include "hong8yung_netlib.h"
#include <winsock.h>
#include <stdio.h>
#include <windows.h>
#include <IPHlpApi.h>

#pragma comment(lib, "iphlpapi.lib")

void print_IPinfo();

int main()
{
	

	print_IPinfo();
	
	return 0;
}
void print_IPinfo() {
	// Declare a point 
	FIXED_INFO *pFixedInfo;
	IP_ADDR_STRING *pIPAddr;

	ULONG ulOutBufLen;
	DWORD dwRetVal;

	// Allocate memory for the structures
	pFixedInfo = (FIXED_INFO *)malloc(sizeof(FIXED_INFO));
	ulOutBufLen = sizeof(FIXED_INFO);

	// to get size requeired for the OutBufLen 
	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pFixedInfo);
		pFixedInfo = (FIXED_INFO *)malloc(ulOutBufLen);
		if (pFixedInfo == NULL) 
			printf("Error allocating memory needed to call GetNetworkParams\n");
	}

	// using general error checking
	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) != NO_ERROR) {
		printf("GetNetworkParams failed with error %d\n", dwRetVal);
		if (pFixedInfo) 
			free(pFixedInfo);
	}

	// case by successful
	printf("\tHost Name: %s\n", pFixedInfo->HostName);
	printf("\tDomain Name: %s\n", pFixedInfo->DomainName);
	printf("\tDNS Servers:\n");
	printf("\t\t%s\n", pFixedInfo->DnsServerList.IpAddress.String);

	pIPAddr = pFixedInfo->DnsServerList.Next;
	while (pIPAddr) {
		printf("\t\t%s\n", pIPAddr->IpAddress.String);
		pIPAddr = pIPAddr->Next;
	}

	printf("\tNode Type: ");
	switch (pFixedInfo->NodeType) {
	case 1:
		printf("%s\n", "Broadcast");
		break;
	case 2:
		printf("%s\n", "Peer to peer");
		break;
	case 4:
		printf("%s\n", "Mixed");
		break;
	case 8:
		printf("%s\n", "Hybrid");
		break;
	default:
		printf("\n");
	}

	printf("\tNetBIOS Scope ID: %s\n", pFixedInfo->ScopeId);

	if (pFixedInfo->EnableRouting)
		printf("\tIP Routing Enabled: Yes\n");
	else
		printf("\tIP Routing Enabled: No\n");

	if (pFixedInfo->EnableProxy)
		printf("\tWINS Proxy Enabled: Yes\n");
	else
		printf("\tWINS Proxy Enabled: No\n");

	if (pFixedInfo->EnableDns)
		printf("\tNetBIOS Resolution Uses DNS: Yes\n");
	else
		printf("\tNetBIOS Resolution Uses DNS: No\n");

	// Free memory
	if (pFixedInfo) {
		free(pFixedInfo);
		pFixedInfo = NULL;
	}
}

void print_MAC(u_int8_t * mac) {
	for (int i = 0; i<6; i++) {
		printf("%02X", *(mac + i));
		if (5 != i) printf(":");
		else printf("\n");
	}
}

void print_IP(unsigned long ip) {
	for (int i = 0; i<4; i++) {
		printf("%d", *((unsigned char*)(&ip) + (3 - i)));
		if (3 != i) printf(".");
		else printf("\n");
	}
}