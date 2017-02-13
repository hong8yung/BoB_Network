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

int enpack_udp(IPv4Address ipdadr, uint16_t udpt, void* data, int ret){
    struct iphdr fake_iphdr;
    struct udphdr fake_udphdr;
    memcpy(&fake_iphdr, (unsigned char *)data,sizeof(fake_iphdr));  // !!! need except try ip header len != 40?


    fake_iphdr.daddr = uint32_t(ipdadr);
    fake_udphdr.uh_sport = htons(28888);
    fake_udphdr.uh_dport = htons(udpt);
    fake_iphdr.protocol = 17;
    fake_udphdr.len = htons(ret+sizeof(fake_iphdr)+sizeof(fake_udphdr));

    memcpy((unsigned char *)data +sizeof(fake_iphdr)+sizeof(fake_udphdr), data, sizeof(fake_iphdr)+sizeof(fake_udphdr));    // backup


    memcpy((unsigned char *)data, &fake_iphdr, sizeof(fake_iphdr));
    memcpy((unsigned char *)data+sizeof(fake_iphdr), &fake_udphdr, sizeof(fake_udphdr));

    hexdump((unsigned char *)data, ret);
    cout << endl <<"dport :: " << ntohs(fake_udphdr.uh_dport) << endl;
    //hexdump((unsigned char *)data, ret);

    return ret+sizeof(fake_iphdr)+sizeof(fake_udphdr);
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
        IPv4Address proxy_server_addr("121.186.5.123");
        //IPv4Address proxy_server_addr("192.168.231.146");
        uint16_t proxy_dport = 17777;

        ret = enpack_udp(proxy_server_addr, proxy_dport, data, ret);

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
        qh = nfq_create_queue(h,  0, &cb2, NULL);
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
