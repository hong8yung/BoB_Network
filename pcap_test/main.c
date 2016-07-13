#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#define TYP_INIT 0
#define TYP_SMLE 1
#define TYP_BIGE 2

unsigned long long htonll(unsigned long long src) {
  static int typ = TYP_INIT;
  unsigned char c;
  union {
    unsigned long long ull;
    unsigned char c[8];
  } x;
  if (typ == TYP_INIT) {
    x.ull = 0x01;
    typ = (x.c[7] == 0x01ULL) ? TYP_BIGE : TYP_SMLE;
  }
  if (typ == TYP_BIGE)
    return src;
  x.ull = src;
  c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c;
  c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c;
  c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c;
  c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c;
  return x.ull;
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char * spNetDevName = pcap_lookupdev(errbuf);
    const char *pcap_v;
    pcap_t* pDes;
    const u_char* ucData;

    int res;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;

    unsigned short dport, sport;
    unsigned long dip, sip;
    unsigned long long dm, sm;

    //unsiged short dport = *((unsigned short*)&(tcp_hdr[2]));

    pcap_v = pcap_lib_version();

    printf("Libcap Version: %s \n",pcap_v);

    if(0 == spNetDevName){
        printf("errbuf  :[%s]\n",errbuf);
        return 100;
    }else{
        printf("Network Device Name : [%s]\n", spNetDevName);
    }

    pDes = pcap_open_live(spNetDevName, 1500, 1 ,0, errbuf);
    if(0 == pDes){
        printf("[-]Error : [%s]\n",errbuf);
        return 101;
    }else{
        printf("[+]Network Device Ready!\n");
        //iDatalink = pcap_datalink(pDes);
    }

    res = pcap_next_ex(pDes, &header, &pkt_data);
    printf("packet data : %d : %llX\n", header->len, pkt_data);

    for(int i=0; i<38; i++){
        if(!(i%8)) printf("\n");
        printf("%02X ",*(pkt_data+i));
    }

    //dm = ntohll(*((unsigned long long*)(pkt_data+0)));
    //sm = ntohll(*((unsigned long long*)&(pkt_data[6])));
    sip = ntohl(*((unsigned long*)&(pkt_data[26])));
    dip = ntohl(*((unsigned long*)&(pkt_data[30])));

    sport = ntohs(*((unsigned short*)&(pkt_data[34])));
    dport = ntohs(*((unsigned short*)&(pkt_data[36])));

    printf("\nSource Ip : ");
    print_IP(sip);

    /*
    for(int i=0; i<4; i++){
        unsigned char tmp = *((unsigned char*)(&sip)+(3-i));
        printf("%d",tmp);
        if(i!=3) printf(".");
        else printf("\n");
    }*/

    printf("Destination Ip : ");
    for(int i=0; i<4; i++){
        unsigned char tmp = *((unsigned char*)(&dip)+(3-i));
        printf("%d",tmp);
        if(i!=3) printf(".");
        else printf("\n");
    }

    printf("\nSource Port : %d\n",sport);
    printf("Destination Port : %d\n",dport);

    printf("\n");
    return 0;
}

void print_IP(unsigned long ip){
    for(int i; i<4; i++){
        printf("%d",*((unsigned char*)(&ip)+(3-i)));
        if(3!=i) printf(".");
        else printf("\n");
    }
}
