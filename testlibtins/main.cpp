#include <tins/tins.h>
#include <iostream>
#include <stddef.h>

using namespace Tins;
using namespace std;

size_t counter(0);

bool count_packets(const PDU &){
    counter++;

    return true;
}

main(){
    //to resolve
    IPv4Address to_resolve("192.168.231.2"); // gateway ip addr
    NetworkInterface iface(to_resolve);
    auto info = iface.addresses();
    EthernetII eth = ARP::make_arp_request(to_resolve, info.ip_addr, info.hw_addr);

    //the sender
    PacketSender sender;
    unique_ptr<PDU> response(sender.send_recv(eth, iface));

    if(response){
        const ARP &arp = response->rfind_pdu<ARP>();
        cout << "Hardware address: " << arp.sender_hw_addr() << endl;
    }
}
