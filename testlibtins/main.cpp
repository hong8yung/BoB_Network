#include <vector>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

int main(){
    vector<Packet> vt;

    Sniffer sniffer("ens33");
    while(vt.size() != 10){
        vt.push_back(sniffer.next_packet());
    }   // save ten packets

    for (const auto& packet : vt){
        if(packet.pdu()->find_pdu<IP>()){
            cout << "At: " << packet.timestamp().seconds()
                 << " - " << packet.pdu()->rfind_pdu<IP>().src_addr()
                 << endl;
        }
    }
}
