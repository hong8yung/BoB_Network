#include <iostream>
#include <tins/tins.h>
#include <unordered_map>

using namespace std;
using namespace Tins;

unordered_map<string, string> ap;

void print_window(unordered_map<string, string> ap){
    for(auto i = ap.begin(); i!=ap.end(); i++){
        cout << "bssid : " << i->first << endl;
    }

}

void print_beacon(const Dot11Beacon &beacon){
    cout << "bssid : " << beacon.addr2() << endl;
    cout << "essid : " << beacon.ssid() << endl;
}

bool callback(const PDU &pdu) {

    const RadioTap &tap = pdu.rfind_pdu<RadioTap>();
    const Dot11Beacon &beacon = pdu.rfind_pdu<Dot11Beacon>();

    if(ap.find(beacon.addr2()) == ap.end()){
        ap.insert(pair<string, string>(beacon.addr2(),beacon.ssid()));
    }else{

    }

    print_beacon(beacon);

    return true;
}


int main(int argc, char *argv[])
{
    // need use number
    string driv_name;

    if(!argv[1]) driv_name = "net0"; //default drive name 'net0'
    else driv_name = argv[1];

    cout << driv_name << endl;

    Sniffer(driv_name).sniff_loop(callback);

    return 0;
}
