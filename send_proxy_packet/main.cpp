#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <tins/tins.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <netinet/udp.h>

using namespace std;
using namespace Tins;

static bool conti = true;


uint16_t ip_chsum_calc(uint16_t ip_hdrlen, uint16_t *p16_iphdr){
    uint32_t sum = 0;
    iphdr * ip_info = (iphdr *)p16_iphdr;

    // set checksum file to null
    ip_info->check = 0;

    // sum of ipheader
    for(int i=0; i<ip_hdrlen/2; i++){
        sum = sum + (u_int)(ntohs(p16_iphdr[i]));
    }

    while( sum >> 16 )
        sum = ( sum & 0xFFFF ) + ( sum >> 16 );

    sum = ~sum;
    return (uint16_t)sum;
}

uint16_t tcp_chsum_calc(iphdr* ipHdr, tcphdr* tcpHdr)
{
  int i;
  int tcpHdrDataLen;
  uint32_t src, dst;
  uint32_t sum=0;
  uint16_t *p;


  tcpHdrDataLen = ntohs(ipHdr->tot_len) - sizeof(iphdr);

  // Add tcpHdr and data buffer as array of UIN16
  p = (uint16_t*)tcpHdr;
  for (i = 0; i < tcpHdrDataLen / 2; i++)
  {
    sum += htons(*p);
    p++;
  }

  // If length is odd, add last data(padding)
  if ((tcpHdrDataLen / 2) * 2 != tcpHdrDataLen)
    sum += (htons(*p) & 0xFF00);

  // Decrease checksum from sum
  sum -= ntohs(tcpHdr->th_sum);

  // Add src address
  src = ntohl(ipHdr->saddr);
  sum += ((src & 0xFFFF0000) >> 16) + (src & 0x0000FFFF);

  // Add dst address
  dst = ntohl(ipHdr->daddr);
  sum += ((dst & 0xFFFF0000) >> 16) + (dst & 0x0000FFFF);

  // Add extra information
  sum += (uint32_t)(tcpHdrDataLen) + IPPROTO_TCP;

  // Recalculate sum
  while(sum >> 16)
  {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  sum = ~sum;

  return (uint16_t)sum;
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

void hexdump(unsigned char * buf, int size){
    int i;
    for(i=0; i<size; i++){
        if(i%16==0) printf("\n");
        printf("%02X ", buf[i]);
    }
    cout << "!!!!!!!!!!!!" << endl;
}

bool chk_url(unsigned char * buf){
    struct iphdr * ip_info = (struct iphdr *)buf;
    if(!ip_info) return false;

    struct tcphdr * tcp_info = (struct tcphdr *)(buf + (ip_info->ihl*4));
    if(!tcp_info) return false;

    unsigned char * http_info = buf + (ip_info->ihl*4) + (tcp_info->doff*4);

    if(!http_info) return false;
    //check err point addr

    //if(tcp_info->dest !=80) return false;   //
    char *tmp_url = "Host: www.sex.com\r\n";
    //char *tmp_url = "Host: daum.net";

    char * p = my_strstr((char *)http_info, (const char *)tmp_url, 50);

    printf("p = %lld", p);

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

bool chk_nfp(unsigned char * buf){
    struct iphdr * ip_info = (struct iphdr *)buf;
    if(!ip_info) return false;

    struct tcphdr * tcp_info = (struct tcphdr *)(buf + (ip_info->ihl*4));
    if(!tcp_info) return false;

    unsigned char * http_info = buf + (ip_info->ihl*4) + (tcp_info->doff*4);

    if(!http_info) return false;
    //check err point addr

    //if(tcp_info->dest !=80) return false;   //
    char *tmp_url = "HTTP/1.1 404 Not Found\r\n";
    //char *tmp_url = "Host: daum.net";

    char * p = my_strstr((char *)http_info, (const char *)tmp_url,50);

    if(p)   return true;
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


int change_pack(IPv4Address ipdadr, void* data, int ret){
    struct iphdr fake_iphdr, *p_iphdr;
    struct tcphdr *p_tcphdr;

    p_iphdr = (iphdr *)data;
    (*(uint32_t*)((unsigned char*)p_iphdr + 16)) = uint32_t(ipdadr);
    //memcpy((unsigned char*)data+, (unsigned char *)data,(p_iphdr->ihl)*4);  // !!! need except try ip header len != 40?

    p_iphdr->check = htons(ip_chsum_calc(((uint16_t)(p_iphdr->ihl))*4, (uint16_t *)p_iphdr));

    p_tcphdr = (tcphdr *)(data+(p_iphdr->ihl)*4);
    (*(uint16_t*)((unsigned char*)p_tcphdr + 2)) = htons(uint16_t(28888));

    p_tcphdr->check = htons(tcp_chsum_calc(p_iphdr, p_tcphdr));

    hexdump((unsigned char *)data, ret);
    //hexdump((unsigned char *)data, ret);

    return ret;
}

int enpack_http(void* data, int ret){
    struct iphdr fake_iphdr, *p_iphdr;
    struct tcphdr fake_tcphdr, *p_tcphdr;
    int fake_hdl, real_pacl;
    unsigned char* tmp_data[1500], *p_http;
    char * fake_header = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";

    p_iphdr = (iphdr *)data;
    p_iphdr->tot_len += htons(40);
    p_iphdr->check = htons(ip_chsum_calc(((uint16_t)(p_iphdr->ihl))*4, (uint16_t *)p_iphdr));

    p_tcphdr = (tcphdr *)(data+(p_iphdr->ihl)*4);

    p_http = (unsigned char *)(p_tcphdr)+(p_tcphdr->doff)*4;

    real_pacl = ret-((p_iphdr->ihl)*4)-((p_tcphdr->doff)*4);

    memcpy(tmp_data,p_http,real_pacl);
    memcpy(p_http, fake_header, 40);
    memcpy(p_http+40,tmp_data, real_pacl);

    p_tcphdr->check = htons(tcp_chsum_calc(p_iphdr, p_tcphdr));

    cout << fake_header << endl;
    hexdump((unsigned char *)data, ret+40);
    cout << "checksume = " << p_iphdr->check << endl;

    return ret+40;
}

int enpack_tcp(IPv4Address ipdadr, uint16_t utcp, void* data, int ret){
    struct iphdr fake_iphdr, *p_iphdr;
    struct tcphdr fake_tcphdr, *p_tcphdr;
    int fake_hdl, real_pacl;
    unsigned char* tmp_data[1500];

    p_iphdr = (iphdr *)data;
    memcpy(&fake_iphdr, (unsigned char *)data,(p_iphdr->ihl)*4);

    p_tcphdr = (tcphdr *)(data+(p_iphdr->ihl)*4);
    memcpy(&fake_tcphdr, (unsigned char *)data+(p_iphdr->ihl)*4,(p_tcphdr->doff)*4);


    fake_iphdr.daddr = uint32_t(ipdadr);
    fake_iphdr.protocol = IPPROTO_TCP;

    fake_tcphdr.source = htons(28888);
    fake_tcphdr.dest = htons(utcp);

    fake_hdl = (p_iphdr->ihl)*4+(p_tcphdr->doff)*4;

    fake_iphdr.tot_len += htons(fake_hdl);
    real_pacl = ret+fake_hdl;

    //memcpy((unsigned char *)data +fake_hdl, data, ret);    // backup
    memcpy(tmp_data, data, ret);

    memcpy((unsigned char *)data, &fake_iphdr, (fake_iphdr.ihl)*4);
    memcpy((unsigned char *)data+(fake_iphdr.ihl)*4, &fake_tcphdr, (fake_tcphdr.doff)*4);
    memcpy((unsigned char *)data+fake_hdl, tmp_data, ret);

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
    if(chk_url((unsigned char*)data) /*&& conti */ )    {
    //if(1)    {
        conti = false;
        IPv4Address proxy_server_addr("59.2.80.104");   // home
        //IPv4Address proxy_server_addr("172.30.1.56");
        //IPv4Address proxy_server_addr("210.117.183.125");
        uint16_t proxy_dport = 28888;

        //ret = enpack_tcp(proxy_server_addr, proxy_dport, data, ret);
        //ret = change_pack(proxy_server_addr,data,ret);
        ret = enpack_http(data, ret);

        cout << "hey you!" << endl;
        return nfq_set_verdict(qh, id, NF_ACCEPT, ret, (const unsigned char *)data);
    }else if(chk_nfp((unsigned char*)data)){
        hexdump((unsigned char *)data, ret);
        cout << "DROP the bittttttttt!!!!" << endl;
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");

    if(argv[1]){ // server
        cout << "server start ! " << endl;
    } else {    // client
        qh = nfq_create_queue(h,  0, &cb, NULL);
    }
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

/*
int main(int argc, char *argv[])
{

    // The sender
    PacketSender sender;
    // The DNS request
    IP pkt = IP("8.8.8.8") / UDP(53, 1337) / DNS();
    TCP tccp(18888, 18888);
    //tccp.ack_seq()

    // Add the query
    pkt.rfind_pdu<DNS>().add_query({ "www.google.com", DNS::A, DNS::IN });
    // We want the query to be resolverd recursively
    pkt.rfind_pdu<DNS>().recursion_desired(1);

    // Send and receive the response.
    std::unique_ptr<PDU> response(sender.send_recv(pkt));
    // Did we receive anything?
    if (response) {
        // Interpret the response
        DNS dns = response->rfind_pdu<RawPDU>().to<DNS>();
        // Print responses
        for (const auto &record : dns.answers()) {
            std::cout << record.dname() << " - " << record.data() << std::endl;
        }
    }
    return 0;
}*/
