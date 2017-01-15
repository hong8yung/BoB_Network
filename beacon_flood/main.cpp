#include <iostream>
#include <unistd.h>
#include <tins/tins.h>
#include <map>
#include <signal.h>

using namespace Tins;
using namespace std;

void func(int sig){
    cout << "bye :)" << endl;
    exit(1);
}

int main() {
    map<Dot11::address_type, string> m;
    map<Dot11::address_type, string>::iterator i;

    // get vendor number
    NetworkInterface ifc("net0");
    string addr_vend = ifc.hw_address().to_string();

    addr_vend = addr_vend.substr(0,9);

    // input fake list
    m.insert(map<Dot11::address_type,string>::value_type(addr_vend+"00:00:01","길길짱잘생김"));
    m.insert(map<Dot11::address_type,string>::value_type(addr_vend+"00:00:02","새해 복 많이 받으세요"));
    m.insert(map<Dot11::address_type,string>::value_type(addr_vend+"00:00:03","왜 노트북에선 안잡히지"));

    i = m.begin();

    signal(SIGINT, func);   // if INPUT Ctrl+c : exit
    Dot11::address_type dmac = "10:68:3F:8F:0B:77";


    while(true){
        Dot11Beacon beacon;
        beacon.addr1(dmac);
        beacon.addr2(i->first);
        beacon.addr3(beacon.addr2());
        beacon.ssid(i->second);

        beacon.ds_parameter_set(8);
        beacon.supported_rates({1.0f, 5.5f, 11.0f});

        beacon.rsn_information(RSNInformation::wpa2_psk());

        RadioTap tap = RadioTap() / beacon;

        PacketSender sender;
        sender.send(tap, "net0");

        usleep(10000);
        if(++i==m.end()) i=m.begin();
    }
}
