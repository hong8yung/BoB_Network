#include <tins/tins.h>

using namespace Tins;

bool doo(PDU&){
    return false;
}

struct foo{
    void bar(){
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter(("ip src 192.168.0.100"));
        Sniffer sniffer("ens33", config);

        sniffer.sniff_loop(make_sniffer_handler(this, &foo::handle));

        sniffer.sniff_loop(doo);
    }

    bool handle(PDU&){
        return false;
    }
};

int main() {
    foo f;
    f.bar();
 }
