#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <tins/tins.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pcap/pcap.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;
using namespace Tins;

void hexdump(unsigned char * buf, int size){
    int i;
    for(i=0; i<size; i++){
        if(i%16==0) printf("\n");
        printf("%02X ", buf[i]);
    }
}

bool chk_url(unsigned char * buf){
    struct iphdr * ip_info = (struct iphdr *)buf;
    if(!ip_info) return false;

    struct tcphdr * tcp_info = (struct tcphdr *)(buf + sizeof(*ip_info));
    if(!tcp_info) return false;

    unsigned char * http_info = buf + sizeof(*ip_info) + sizeof(*tcp_info);
    if(!http_info) return false;
    //check err point addr

    //if(tcp_info->dest !=80) return false;   //
    char *tmp_url = "Host: www.sex.com";
    char * p = strstr((char *)http_info, (const char *)tmp_url);

    if(p)   return true;
    else return false;
}

bool chk_mypacket(unsigned char * buf){
    struct iphdr * ip_info = (struct iphdr *)buf;
    if(!ip_info) return false;

    struct udphdr * udp_info = (struct udphdr *)(buf + sizeof(*ip_info));
    if(!udp_info) return false;

    hexdump((unsigned char *)udp_info, sizeof(*udp_info));
    cout << "\t port number : " << udp_info->uh_dport<< endl;
    cout << "\t port number : " << ntohs(udp_info->uh_dport)<< endl;

    if(udp_info->uh_dport==28888) return true;

    else return false;
}

void print_IP(unsigned long ip){
    for(int i=0; i<4; i++){
        printf("%d",*((unsigned char*)(&ip)+(3-i)));
        if(3!=i) printf(".");
        else printf("\n");
    }
}



/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);

    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);


    ifi = nfq_get_indev(tb);

    ifi = nfq_get_outdev(tb);
    ifi = nfq_get_physindev(tb);
    ifi = nfq_get_physoutdev(tb);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
    }
    fputc('\n', stdout);

    return id;
}

int enpack_tcp(IPv4Address ipdadr, uint16_t utcp, void* data, int ret){
    struct iphdr fake_iphdr, *p_iphdr;
    struct tcphdr fake_tcphdr, *p_tcphdr;
    int fake_hdl, real_pacl;

    p_iphdr = (iphdr *)data;
    memcpy(&fake_iphdr, (unsigned char *)data,(p_iphdr->ihl)*4);  // !!! need except try ip header len != 40?

    p_tcphdr = (tcphdr *)(data+(p_iphdr->ihl)*4);
    memcpy(&fake_tcphdr, (unsigned char *)data+(p_iphdr->ihl)*4,(p_tcphdr->doff)*4);


    fake_iphdr.daddr = uint32_t(ipdadr);
    fake_iphdr.protocol = IPPROTO_TCP;

    fake_tcphdr.source = htons(28888);
    fake_tcphdr.dest = htons(utcp);

    fake_hdl = (p_iphdr->ihl)*4+(p_tcphdr->doff)*4;
    real_pacl = ret+fake_hdl;

    memcpy((unsigned char *)data +fake_hdl, data, ret);    // backup


    memcpy((unsigned char *)data, &fake_iphdr, (fake_iphdr.ihl)*4);
    memcpy((unsigned char *)data+(fake_iphdr.ihl)*4, &fake_tcphdr, (fake_tcphdr.doff)*4);

    hexdump((unsigned char *)data, ret);
    //hexdump((unsigned char *)data, ret);

    return real_pacl;
}

int depack_udp(void* data, int ret){
    struct iphdr *fake_iphdr;
    struct udphdr fake_udphdr;
    int fake_hdl, real_pacl;

    fake_hdl = (fake_iphdr->ihl)+sizeof(fake_udphdr);
    real_pacl = ret-fake_hdl;

    memcpy((unsigned char *)data, (unsigned char *)data+fake_hdl, real_pacl);
    hexdump((unsigned char *)data, real_pacl);

    return real_pacl;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    int ret = nfq_get_payload(nfa, (unsigned char **)&data);
    if(chk_url((unsigned char*)data))    {
        //IPv4Address proxy_server_addr("121.186.5.123");
        IPv4Address proxy_server_addr("192.168.231.146");
        //IPv4Address proxy_server_addr("210.117.183.125");
        uint16_t proxy_dport = 28888;

        ret = enpack_tcp(proxy_server_addr, proxy_dport, data, ret);

        return nfq_set_verdict(qh, id, NF_ACCEPT, ret, (const unsigned char *)data);
    }
    else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static int cb2(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    int ret = nfq_get_payload(nfa, (unsigned char **)&data);
    if(chk_mypacket((unsigned char*)data))    {

        ret = depack_udp(data, ret);

        return nfq_set_verdict(qh, id, NF_ACCEPT, ret, (const unsigned char *)data);
    }
    else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

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

    unsigned short dport, sport;
    unsigned long dip, sip;
    unsigned char dm[6], sm[6];

    void print_IP(unsigned long ip);

    pcap_v = pcap_lib_version();

    printf("Libcap Version: %s \n",pcap_v);

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

    pDes = pcap_open_live(spNetDevName, 1500, 1 ,0, errbuf);
    if(0 == pDes){
        printf("[-]Error : [%s]\n",errbuf);
        return 101;
    }else{
        printf("[+]Network Device Ready!\n");
    }

    while((res=pcap_next_ex(pDes, &header, &pkt_data))>=0){
        if(ntohs(*((unsigned short*)&(pkt_data[12])))!=TYPE_IP) continue; // case by not follow ip header

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
    return 0;
}
