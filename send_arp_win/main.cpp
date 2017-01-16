
#include "pcap.h"
#include "hong8yung_netlib.h"
#include <winsock.h>
#include <stdio.h>
#include <windows.h>
#include <IPHlpApi.h>
#include <string.h>

#pragma comment(lib, "iphlpapi.lib")

void print_MAC(u_int8_t * mac);
void print_IP(unsigned long ip);
void getAttackerInfo(ULONG* attacker_ip, ULONG* gateway_ip, u_int8_t* attacker_mac, char* spNetDevName);
u_int8_t* getVictim_MAC(pcap_t* pDes, ULONG victim_ip, ULONG attacker_ip, u_int8_t* attacker_mac);
pcap_t* connectIface(char * spNetDevName);

int main(int argc, char *argv[])
{
	pcap_t* pDes = NULL;
	ULONG victim_ip, attacker_ip, gateway_ip;
	u_int8_t  victim_mac[ETHER_ADDR_LEN], attacker_mac[ETHER_ADDR_LEN];
	char spNetDevName[100] ;

	if (inet_pton(AF_INET, argv[1], &victim_ip) != 1) {	// victim ip addr String to ULONG
		printf("[-] Invalid ip address\n");
		//exit(1);
		inet_pton(AF_INET, "172.30.1.47", &victim_ip);
	}
	victim_ip = ntohl(victim_ip);

	pDes = connectIface(spNetDevName);	// Connect PCAP interface
	
	getAttackerInfo(&attacker_ip, &gateway_ip, attacker_mac, spNetDevName);

	memcpy(victim_mac, getVictim_MAC(pDes, victim_ip, attacker_ip, attacker_mac), ETHER_ADDR_LEN);	// get victim mac

	printf("=====Attacker=====\n");
	print_IP(attacker_ip);
	print_MAC(attacker_mac);

	printf("=====Victim=====\n");
	print_IP(victim_ip);
	print_MAC(victim_mac);

	//print_AdapterInfo();
	//print_IPinfo();

	if(pDes) pcap_close(pDes);
	
	return 0;
}

void getAttackerInfo(ULONG* attacker_ip, ULONG* gateway_ip, u_int8_t* attacker_mac, char* spNetDevName) {
	PIP_ADAPTER_INFO pAdapterInfo;
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));

	ULONG buflen = sizeof(IP_ADAPTER_INFO);
	DWORD dwRetVal;

	if (GetAdaptersInfo(pAdapterInfo, &buflen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(buflen);
		if (pAdapterInfo == NULL)
			printf("Error allocating memory needed to call GetAdaptersInfo\n");
	}

	if (dwRetVal = GetAdaptersInfo(pAdapterInfo, &buflen) != NO_ERROR) {
		printf("GetAdaptersInfo failed with error %d\n", dwRetVal);
		if (pAdapterInfo)
			free(pAdapterInfo);
	}

	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	while (pAdapter) {
		if (strstr(spNetDevName, pAdapter->AdapterName)) {	// search seleted Device by name
			inet_pton(AF_INET, pAdapter->IpAddressList.IpAddress.String, attacker_ip);
			inet_pton(AF_INET, pAdapter->GatewayList.IpAddress.String, gateway_ip);
			memcpy(attacker_mac, pAdapter->Address, 6);

			*attacker_ip = ntohl(*attacker_ip);
			*gateway_ip = ntohl(*gateway_ip);
			break;
		}
		pAdapter = pAdapter->Next;
	}

	if (pAdapterInfo) free(pAdapterInfo);
}

pcap_t* connectIface(char * spNetDevName) {
	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *pDes;
	bpf_u_int32 mask, net;

	int res, i, inum;
	struct pcap_pkthdr *header;
	const u_char * pkt_data;
	ETHER_HDR *ether_header;
	IPv4_HDR *ip_header;
	TCP_HDR *tcp_header;

	// Retrieve the device list from the local machine
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldev_ex: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs, i = 0; d != NULL; d = d->next)
	{
		printf("%d device : %s", ++i, d->name);
		
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	printf("enter the interface number: ");
	scanf_s("%d", &inum);
	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++); // jump to the i-th dev

	memset(spNetDevName, 0, 100);
	memcpy(spNetDevName, d->name, strlen(d->name));
	if (pcap_lookupnet(spNetDevName, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", spNetDevName, errbuf);
		net = 0;
		mask = 0;
	}

	pDes = pcap_open_live(spNetDevName, 1500, 1, 1, errbuf);
	if (0 == pDes) {
		printf("[-]Error : [%s]\n", errbuf);
	}
	else {
		printf("[+]Network Device Ready!\n");
	}

	
	return pDes;
}

u_int8_t* getVictim_MAC(pcap_t* pDes, ULONG victim_ip, ULONG attacker_ip, u_int8_t* attacker_mac) {
	ETHER_HDR ehp;
	ARP_HDR ahp;
	UCHAR packetbuf[1500];

	int res;
	struct pcap_pkthdr *header;

	memset(ehp.ether_dhost, 0xff, ETHER_ADDR_LEN);	// set broadcast
	memcpy(ehp.ether_shost, attacker_mac, ETHER_ADDR_LEN);
	ehp.ether_type = htons(ETHERTYPE_ARP);

	ahp.ar_hrd = htons(ARPHRD_ETHER);	// mac type
	ahp.ar_pro = htons(ETHERTYPE_IP);	// protocol type
	ahp.ar_hln = ETHER_ADDR_LEN;	// hadware size
	ahp.ar_pln = 4;	//protocol size
	ahp.ar_op = htons(ARPOP_REQUEST);	// opcode (request = 1)

	memset(packetbuf, 0x00, 1500);	// clear packet buffer

	memcpy(packetbuf, &ehp, sizeof(ETHER_HDR));
	memcpy(packetbuf + sizeof(ETHER_HDR), &ahp, sizeof(ARP_HDR));

	int temp_cnt = sizeof(ETHER_HDR)+sizeof(ARP_HDR);
	
	memcpy(packetbuf + temp_cnt, attacker_mac, ETHER_ADDR_LEN);
	temp_cnt += ETHER_ADDR_LEN;

	*(ULONG *)(packetbuf + temp_cnt) = htonl(attacker_ip);
	temp_cnt += sizeof(attacker_ip);

	memset(packetbuf + temp_cnt, 0x00, ETHER_ADDR_LEN);
	temp_cnt += ETHER_ADDR_LEN;

	*(ULONG *)(packetbuf + temp_cnt) = htonl(victim_ip);

	if (pcap_sendpacket(pDes, packetbuf, sizeof(ETHER_HDR) + sizeof(ARP_HDR) + temp_cnt) != 0) {
		printf("[-] Error sending the ARPpacket to victim\n");
		return 0;
	}

	printf("send ok\n");

	//memset(packetbuf, 0x00, 1500);	// clear packet buffer
	const unsigned char * pkt_data;
	while ((res = pcap_next_ex(pDes, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;

		ETHER_HDR *ch_ehp = (ETHER_HDR *)pkt_data;
		if (ntohs(ch_ehp->ether_type) != ETHERTYPE_ARP) continue;
		else {
			
			ARP_HDR * ch_ahp = (ARP_HDR *)(pkt_data + sizeof(ETHER_HDR));
			if (ntohs(ch_ahp->ar_op) == ARPOP_REPLY) {
				UCHAR* tmpp = (UCHAR*)ch_ahp + sizeof(ARP_HDR);
				if (ntohl(*(ULONG *)(tmpp+ ETHER_ADDR_LEN)) == victim_ip) {
					return tmpp;
				}
			}
		}
	}
	return 0;
	//pcap_sendpacket(pDes,,)
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