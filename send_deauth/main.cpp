#include <iostream>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

int main(int argc, char *argv[])
{
    string if_name;
    HWAddress<6> ap_addr;
    /*
     *  send_deauth <interce name> <ap mac> [<station mac>]
     */

    if(argc < 3){
        /* default option setting */
        if_name = "net0";
        ap_addr = HWAddress<6>("00:07:89:32:0A:9F");

        cout << "send_deauth <interce name> <ap mac> [<station mac>]" << endl;
        //return 0;
    }else{
        if_name = argv[1];
        ap_addr = HWAddress<6>(argv[2]);
    }

    cout << "if_name : " << if_name << endl;
    cout << "ap_addr : " << ap_addr << endl;

    return 0;
}
