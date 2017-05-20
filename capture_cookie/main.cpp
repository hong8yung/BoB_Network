#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <string.h>
#include <net/if.h>
#include <pthread.h>
#include <netinet/in.h>

#define BUFSIZE 8192

using namespace std;

void hexdump(unsigned char * buf, int size){
    int i;
    for(i=0; i<size; i++){
        if(i%16==0) printf("\n");
        printf("%02X ", buf[i]);
    }
}

char* my_strstr(const char *in, const char *str, unsigned int size)
{
    char c;
    size_t len;

    c = *str++;
    if (!c)
        return (char *) in;	// Trivial empty string case

    len = strlen(str);
    //len = size;
    do {
        char sc;

        do {
            size--;
            sc = *in++;
            if (!sc || !size)   // size check
                return (char *) 0;
        } while (sc != c);
    } while (strncmp(in, str, len) != 0);

    return (char *) (in - 1);
}

bool chk_packet(unsigned char * data){

    ether_header * p_eth = (ether_header *)data;

    if(ntohs(p_eth->ether_type)!=ETHERTYPE_IP) return false; // case by not follow ip header

    struct iphdr * ip_info = (struct iphdr *)((u_char *)p_eth+sizeof(ether_header));

    if(!ip_info) return false;

    if(ip_info->protocol != IPPROTO_TCP) return false;
    hexdump(data, 38);
    struct tcphdr * tcp_info = (struct tcphdr *)((u_char *)p_eth + (ip_info->ihl*4));

    if(!tcp_info) return false;

    unsigned char * http_info = (u_char *)p_eth + (ip_info->ihl*4) + (tcp_info->doff*4);

    if(!http_info) return false;

    //if(tcp_info->dest !=80) return false;   //
    char *tmp_url = "Host: www.sex.com\r\n";
    //char *tmp_url = "Host: daum.net";

    char * p = my_strstr((char *)http_info, (const char *)tmp_url, 50);

    //printf("p = %lld", p);
    //return true;

    if(p)   return true;
    else return false;
}

int main(int argc, char *argv[])
{
    const unsigned char *pkt_data;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pDes = pcap_create("net0", error_buffer);

    pcap_set_rfmon(pDes, 1);
    pcap_set_promisc(pDes, 1); /* Capture packets that are not yours */
    pcap_set_snaplen(pDes, 2048); /* Snapshot length */
    pcap_set_timeout(pDes, 1000); /* Timeout in milliseconds */
    pcap_activate(pDes);
    /* handle is ready for use with pcap_next() or pcap_loop() */


    struct pcap_pkthdr* header;


    int res;


    void print_IP(unsigned long ip);


    /*
    if(0 == pDes){
        printf("[-]Error : [%s]\n",errbuf);
        return 101;
    }else{
        printf("[+]Network Device Ready!\n");
    }*/

    while((res=pcap_next_ex(pDes, &header, &pkt_data))>=0){
        if(pkt_data){
            hexdump((unsigned char *)pkt_data, header->caplen);
        }
        if(!chk_packet((unsigned char *)pkt_data)) continue;
        else{
            printf("http packet !!! \n");
            printf("========================================================\n");
        }
    }

    return 0;
}



void print_IP(unsigned long ip){
    for(int i=0; i<4; i++){
        printf("%d",*((unsigned char*)(&ip)+(3-i)));
        if(3!=i) printf(".");
        else printf("\n");
    }
}

void print_MAC(unsigned char * mac){
    for(int i=0; i<6; i++){
        printf("%02X",*(mac+i));
        if(5!=i) printf(":");
        else printf("\n");
    }
}
