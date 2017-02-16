#include <iostream>
#include <tins/tins.h>
#include <unordered_map>

using namespace std;
using namespace Tins;

unordered_map<string, struct AP_info> ap;



void print_window(unordered_map<string, struct AP_info>& ap){
    cout << "\033[2J\033[1;1H";
    for(auto i = ap.begin(); i!=ap.end(); i++){
        cout << "bssid : " << i->first << " : " << (i->second).essid << " : " << (i->second).beacons << endl;
    }
}

void print_beacon(const Dot11Beacon &beacon){
    cout << "bssid : " << beacon.addr2() << endl;
    cout << "essid : " << beacon.ssid() << endl;
}

struct AP_info{
    string essid="";
    uint32_t beacons=0;
    uint32_t pwr = 0;
    uint32_t data = 0;
    uint32_t ch;
    string MB="";
    string ENC="";
    string CIPHER="";
    string AUTH="";
};

bool callback(const PDU &pdu) {

    const RadioTap &tap = pdu.rfind_pdu<RadioTap>();
    const Dot11Beacon &beacon = pdu.rfind_pdu<Dot11Beacon>();
    const Dot11 &dot11 = pdu.rfind_pdu<Dot11>();

    /*
     * enum ManagementSubtypes {
     *  ASSOC_REQ = 0,
     *  ASSOC_RESP = 1,
     *  REASSOC_REQ = 2,
     *  REASSOC_RESP = 3,
     *  PROBE_REQ = 4,
     *  PROBE_RESP = 5,
     *  BEACON = 8,
     *  ATIM = 9,
     *  DISASSOC = 10,
     *  AUTH = 11,
     *  DEAUTH = 12
     * };
     */

    int frame_type = dot11.subtype();
    if(frame_type == Dot11::BEACON){    // beacon packet
        if(ap.find(beacon.addr2().to_string()) == ap.end()){
            struct AP_info tmp_AP;
            tmp_AP.essid = beacon.ssid();
            tmp_AP.beacons = 1;
            tmp_AP.ch = tap.channel_freq();
            ap.insert(pair<string, AP_info>(beacon.addr2().to_string(),tmp_AP));
        }else{
            (ap.find(beacon.addr2().to_string())->second).beacons++;
        }
    }else{  // data packet

    }



    print_window(ap);`
    //print_beacon(beacon);

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
