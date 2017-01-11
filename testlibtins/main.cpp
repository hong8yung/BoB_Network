#include <tins/tins.h>
#include <iostream>
#include <stddef.h>

using namespace Tins;
using namespace std;

size_t counter(0);

bool count_packets(const PDU &){
    counter++;

    return true;
}

main(){
    FileSniffer sniffer("/tmp/some_pcap_file.pcap");
    sniffer.sniff_loop(count_packets);
    cout << "There are " << counter << "packets in the pcap file" << endl;
}
