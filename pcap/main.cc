#include "pcap/pcap.h"
#include <string>
#include <cstring>
#include <iostream>
#include <stdint.h>

#include "lib.h"

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    memset(errbuf, 0, sizeof(errbuf));

    pcap_t *p1, *p2;
    pcap_if_t *ifs, *d;

    p1 = pcap_open_live("eth0", 65535, 1, 0, errbuf);
    
    p2 = pcap_open_live("eth0", 65535, 1, 0, errbuf);

    if(p1 != NULL && p2 != NULL)
    {
        std::cout << "session on the same interface created successfully\n";
    }


}


