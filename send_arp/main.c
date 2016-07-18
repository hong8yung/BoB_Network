#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char * spNetDevName = pcap_lookupdev(errbuf);
    const char *pcap_v;
    pcap_t* pDes;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    int res;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;

    if(0 == spNetDevName){
        printf("errbuf  :[%s]\n",errbuf);
        return 100;
    }else{
        printf("Network Device Name : [%s]\n", spNetDevName);
    }

    if (pcap_lookupnet(spNetDevName, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", spNetDevName, errbuf);
                net = 0;
                mask = 0;
            }

    pDes = pcap_open_live(spNetDevName, 1500, 1 , 1, errbuf);
    if(0 == pDes){
        printf("[-]Error : [%s]\n",errbuf);
        return 101;
    }else{
        printf("[+]Network Device Ready!\n");
    }


    struct ether_header *ehp;

    res = pcap_next_ex(pDes, &header, &pkt_data);

    if(res >= 0){
        ehp = (struct ether_header *)pkt_data;

        for(int i=0; i<38; i++){    // print for header(HEX)
            if(!(i%8)) printf("\n");
            printf("%02X ",*(pkt_data+i));
        }

        printf("DM : ");
        print_MAC(ehp->ether_dhost);
        printf("SM : ");
        print_MAC(ehp->ether_shost);
    }


    /*
    while((res=pcap_next_ex(pDes, &header, &pkt_data))>=0){
        for(int i=0; i<38; i++){    // print for header(HEX)
            if(!(i%8)) printf("\n");
            printf("%02X ",*(pkt_data+i));
        }
        printf("\n");

        for(int i=0; i<6; i++){
            dm[i] = (pkt_data[DM+i]);
        }

        for(int i=0; i<6; i++){
            sm[i] = (pkt_data[SM+i]);
        }

        printf("\nSource Mac : ");
        print_MAC(sm);

        printf("Destination Mac : ");
        print_MAC(dm);

        sip = ntohl(*((unsigned long*)&(pkt_data[SIP])));
        dip = ntohl(*((unsigned long*)&(pkt_data[DIP])));

        printf("\nSource Ip : ");
        print_IP(sip);

        printf("Destination Ip : ");
        print_IP(dip);

        if((pkt_data[PID]==IP_TCP)||(pkt_data[PID]==IP_UDP)){
            sport = ntohs(*((unsigned short*)&(pkt_data[SPORT])));
            dport = ntohs(*((unsigned short*)&(pkt_data[DPORT])));

            printf("\nSource Port : %d\n",sport);
            printf("Destination Port : %d\n",dport);
        }else{
             printf("\nNot UDP or TCP Protocol\n");
        }
        printf("========================================================\n");
    }
    */
    return 0;
}

void print_IP(unsigned long ip){
    for(int i=0; i<4; i++){
        printf("%d",*((unsigned char*)(&ip)+(3-i)));
        if(3!=i) printf(".");
        else printf("\n");
    }
}

void print_MAC(u_int8_t * mac){
    for(int i=0; i<6; i++){
        printf("%02X",*(mac+i));
        if(5!=i) printf(":");
        else printf("\n");
    }
}
