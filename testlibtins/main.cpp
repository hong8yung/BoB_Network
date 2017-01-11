#include <iostream>
#include <tins/tins.h>
#include <cassert>
#include <string>

using namespace Tins;

bool callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>(); // Find the IP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>(); // Find the TCP layer
    std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
              << ip.dst_addr() << ':' << tcp.dport() << std::endl;
    return true;
}

int main() {
    //Sniffer("net0").sniff_loop(callback);
    SnifferConfiguration config;
    config.set_filter("port 80");
    config.set_promisc_mode(true);
    config.set_snap_len(400);
    Sniffer sniffer("net0", config);
    sniffer.set_filter("ip src 192.168.0.1");   // set filter
    PDU *some_pdu = sniffer.next_packet();

    delete some_pdu;
 }
