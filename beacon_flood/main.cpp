#include <iostream>
#include <tins/tins.h>

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
    PacketSender sender;
    Dot11Beacon beacon;
    //beacon.addr1("10:68:3f:8f:0b:77");
    beacon.addr1(Dot11::BROADCAST);
    beacon.addr2("00:01:02:03:04:05");
    beacon.addr3(beacon.addr2());

    beacon.ssid("libtins");
    beacon.ds_parameter_set(8);
    beacon.supported_rates({1.0f, 5.5f, 11.0f});
    beacon.rsn_information(RSNInformation::wpa2_psk());
    RadioTap radio = RadioTap() / beacon;

    sender.send(radio, "net0");
    sender.close_socket();
}
