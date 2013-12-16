#include "bd_sniffer.h"

#include <cstring>
#include <stdint.h>

#include "pcap.h"

bd_sniffer* bd_sniffer::_instance = NULL;

void test(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{

}

bd_sniffer::bd_sniffer():
   _sess(0), _init_flag(0)
{
}

bd_sniffer::~bd_sniffer()
{
    if(_sess != 0)
    {
        delete _sess;
    }
}

bd_sniffer* bd_sniffer::getInstance()
{
    if(_instance == NULL)
    {
        _instance = new bd_sniffer();
    }
    return _instance;
}

uint8_t bd_sniffer::callbackRegister(pkt_handler_t hdr, handler_type_e idx)
{
    uint8_t rc; // result code

    if(hdr == NULL || idx >= HANDLER_TYPE_MAX)
    {
        return SNIFFER_ERR;
    }

    if(NULL != _handlers[idx])
    {
        rc = SNIFFER_ERR_HANDLER;
    }

    _handlers[idx] = hdr;
    
    return (rc = SNIFFER_OK);
}

int bd_sniffer::callbackDeregister(handler_type_e idx)
{
    if(idx >= HANDLER_TYPE_MAX)
    {
        return SNIFFER_ERR;
    }

    _handlers[idx] = NULL;

    return SNIFFER_OK;
}

int bd_sniffer::init(const std::string& deviceName, const std::string& filter,uint32_t promisc)
{
    if(isInit())
    {
        return SNIFFER_OK;
    }

    result_code_e rc = SNIFFER_OK;

    _sess = new bd_pcap_session(deviceName, filter, 65535/*pkt length*/, promisc);
    if(! _sess->isLive())
    {
        delete _sess;
        _sess = NULL;
        _init_flag = 0;
        return rc = SNIFFER_ERR_INIT;
    }
    _init_flag = 1;

    return rc;
}

uint8_t bd_sniffer::isInit()
{
    return _init_flag;
}

int bd_sniffer::activate()
{
    if(isInit())
    {
        _sess->startCap((pcap_handler)this._l, NULL);
    }
}

void bd_sniffer::_l(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
    ethernet_header *e_p = (ethernet_header *)packet;
    ip *ip_p = NULL;
    /// network layer pakcet poiner
    const u_char *network_p = NULL;
    uint16_t ether_type;

    /// The type field larger than 1500 means that it's a Ethernet II protocol
    if(e_p -> v.type > 1500)
    {
        ether_type = e_p -> v.type;
        network_p = packet + 14;
    }
    else
    {
        /// if it's 802.2 LLC with SNAP
        if(e_p->v.llc_hdr.dsap == 0xAA && e_p->v.llc_hdr.ssap == 0xAA)
        {
            /// ether:mac(14)+llc(3)+snap(5)
            /// snap:OUI(3) + ethertype(2)
            ether_type = e_p + 20;
            network_p = e_p + 22;
        }
        /// tcp/ip is not implemented in 802.2 LLC without SNAP
        else
        {
            return;
        }
    }

    switch(ether_type)
    {
        case PROTO_IPV4:
            if(IS_REGISTERED(HANDLER_TCP))
            {
                ip_p = (ip *)network_p;

                switch(ip_p->ip_p)
                {
                    case IPPROTO_TCP:
                        break;
                    case IPPROTO_UDP:
                        break;
                    case IPPROTO_ICMP:
                        break;
                    case IPPROTO_IGMP:
                        break;
                    default:
                }
            }
            break;
        case PROTO_ARP:
            if(IS_REGISTERED(HANDLER_ARP))
            {
                (*(_handlers[HANDLER_ARP]))(network_p);
            }
            break;
        case PROTO_ICMP:
            if(IS_REGISTERED(HANDLER_ICMP))
            {
                (*(_handlers[HANDLER_ICMP]))(network_p);
            }
            break;
        case PROTO_IGMP:
            if(IS_REGISTERED(HANDLER_IGMP))
            {
                (*(_handlers[HANDLER_IGMP]))(network_p);
            }
            break;
        default:
            break;
            // default action
    }
}


