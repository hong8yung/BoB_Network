#include "pcap.h"
#include "hong8yung_netlib.h"

int main()
{

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