#define HAVE_REMOTE
#include "pcap.h"
#include "packet_header.h"

#include <stdio.h>

int main()
{
	pcap_if_t *alldevs, *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	char *spNetDevName;
	pcap_t *pDes;
	bpf_u_int32 mask, net;

	// Retrieve the device list from the local machine
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldev_ex: %s\n", errbuf);
		exit(1);
	}

	spNetDevName = alldevs->name;

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



	return 0;
}