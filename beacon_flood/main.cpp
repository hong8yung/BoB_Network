#include <iostream>
#include <unistd.h>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

int main() {
    while(true){
    Dot11Beacon beacon;
    beacon.addr1(Dot11::BROADCAST);
    beacon.addr2("00:11:22:33:44:55");
    beacon.addr3(beacon.addr2());
    beacon.addr4(beacon.addr2());

    beacon.ssid("testing.");

    beacon.ds_parameter_set(8);
    beacon.supported_rates({1.0f, 5.5f, 11.0f});

    //beacon.rsn_information(RSNInformation::wpa2_psk());

    RadioTap tap = RadioTap() / beacon;


    PacketSender sender;
    sender.send(tap, "net0");

    usleep(10000);
    }
    cout << "send! okay?" << endl;
}
