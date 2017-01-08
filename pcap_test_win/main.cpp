#define HAVE_REMOTE
#include "pcap.h"
#include "hong8yung_netlib.h"

#include <stdio.h>

int main()
{
	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	char *spNetDevName;
	pcap_t *pDes;
	bpf_u_int32 mask, net;

	int res, i, inum;
	struct pcap_pkthdr *header;
	const u_char * pkt_data;
	ETHER_HDR *ether_header;
	IPv4_HDR *ip_header;
	TCP_HDR *tcp_header;

	void print_IP(unsigned long ip);
	void print_MAC(UCHAR * mac);

	// Retrieve the device list from the local machine
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldev_ex: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs, i=0; d != NULL; d = d->next)
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

	spNetDevName = d->name;

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

	while ((res = pcap_next_ex(pDes, &header, &pkt_data)) >= 0) {
		if (!res) continue;	// case : time out
		
		ether_header = (ETHER_HDR *)pkt_data;
		if (ntohs(ether_header->ether_type) != ETHERTYPE_IP) continue;

		printf("\nSource Mac : ");
		print_MAC(ether_header->ether_shost);

		printf("Destination Mac : ");
		print_MAC(ether_header->ether_dhost);

		ip_header = (IPv4_HDR *)(pkt_data + sizeof(ETHER_HDR));
		printf("Source IP : ");
		print_IP(ntohl(*((ULONG*)&(ip_header->ip_src))));

		printf("Destination IP : ");
		print_IP(ntohl(*((ULONG*)&(ip_header->ip_dst))));

		for (int i = 0; i<38; i++) {    // print for header(HEX)
			if (!(i % 8)) printf("\n");
			printf("%02X ", *(pkt_data + i));
		}

		printf("\n=======================\n");

	}

	pcap_close(pDes);

	return 0;
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