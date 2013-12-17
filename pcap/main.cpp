#include "pcap/pcap.h"
#include "bd_sniffer.h"
#include <string>
#include <cstring>
#include <iostream>
#include <stdint.h>

#include "lib.h"
#define _DEBUG
#include "trace.h"

void processPkt(const u_char *pkt);
int main()
{
    int rz;
    std::string eth("eth0");
    std::string fil;
    if(rz = bd_sniffer::getInstance().init(eth, fil, 1))
    {
        std::cout << "bd_sniffer err, code:" << rz << std::endl;
        return 1;
    }

    bd_sniffer::getInstance().callbackRegister(processPkt, HANDLER_UDP);

    bd_sniffer::getInstance().activate();
}

void processPkt(const u_char *pkt)
{
    std::cout << "captured data:" << std::endl;
    TRACE("%02x%02x%02x%02x%02x%02x%02x\n", *pkt, *(pkt+1), *(pkt+2), *(pkt+3), *(pkt+4),
            *(pkt+5), *(pkt+6));
}
