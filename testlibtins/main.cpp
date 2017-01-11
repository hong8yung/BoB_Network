#include <tins/tins.h>
#include <iostream>
#include <stddef.h>

using namespace Tins;
using namespace std;

main(){
    PacketSender sender;
    IP pkt = IP("8.8.8.8") / UDP(53, 1337) / DNS();
    pkt.rfind_pdu<DNS>().add_query({"www.google.com", DNS::A, DNS::IN});
    pkt.rfind_pdu<DNS>().recursion_desired(1);

    unique_ptr<PDU> response(sender.send_recv(pkt));
    if(response){
        DNS dns = response->rfind_pdu<RawPDU>().to<DNS>();
        for(const auto &record : dns.answers()){
            cout << record.dname() << " - " << record.data() << endl;
        }
    }
}
