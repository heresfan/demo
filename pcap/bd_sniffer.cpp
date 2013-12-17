#include "bd_sniffer.h"

#include <cstring>
#include <stdint.h>
#include <iostream>
#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

#include "pcap.h"

#define _DEBUG
#include "trace.h"

bd_sniffer* bd_sniffer::_instance = NULL;
pkt_handler_t bd_sniffer::_handlers[HANDLER_TYPE_MAX];

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

bd_sniffer& bd_sniffer::getInstance()
{
    if(_instance == NULL)
    {
        _instance = new bd_sniffer();
    }
    return *_instance;
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
        return rc = SNIFFER_ERR_HANDLER;
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
        _sess->startCap((pcap_handler)&_l, NULL);
    }
}

void bd_sniffer::_l(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
    //TRACE("_l entry\n");
    ethernet_header *e_p = (ethernet_header *)packet;
    ip *ip_p = NULL;
    /// network layer pakcet poiner
    const u_char *network_p = NULL;
    uint16_t ether_type = ntohs(e_p -> v.type);
    uint8_t ip_type = 0; /*0 for ip*/

    /// The type field larger than 1500 means that it's a Ethernet II protocol
    if(ether_type > 1500)
    {
        //TRACE("ether II packet\n");
        //TRACE("dest mac:%x:%x:%x:%x:%x:%x\n", e_p->dst_mac[0], e_p->dst_mac[1],
        //        e_p->dst_mac[2], e_p->dst_mac[3],
        //        e_p->dst_mac[4],e_p->dst_mac[5]);
        //TRACE("src mac:%x:%x:%x:%x:%x:%x\n", e_p->src_mac[0], e_p->src_mac[1],
        //        e_p->src_mac[2], e_p->src_mac[3],
        //        e_p->src_mac[4],e_p->src_mac[5]);
        network_p = packet + 14;
    }
    else
    {
        //TRACE("802.2 LLC packet\n");
        //TRACE("len:%d\n", e_p->v.llc_hdr.size);
        /// if it's 802.2 LLC with SNAP
        if(e_p->v.llc_hdr.dsap == 0xAA && e_p->v.llc_hdr.ssap == 0xAA)
        {
            /// ether:mac(14)+llc(3)+snap(5)
            /// snap:OUI(3) + ethertype(2)
            ether_type = *(uint16_t *)(e_p + 1);
            network_p = (u_char *)e_p + 22;
        }
        /// tcp/ip is not implemented in 802.2 LLC without SNAP
        else
        {
            return;
        }
    }
    //TRACE("ether type:0x%x\n", ether_type);
    switch(ether_type)
    {
        case PROTO_IPV4:
            if(IS_REGISTERED(HANDLER_IPV4))
            {
                (*(_handlers[HANDLER_IPV4]))(network_p);
            }
            ip_p = (ip *)network_p;
            ip_type = ip_p->ip_p;
            //TRACE("iptype:%d\n", ip_type);
            switch(ip_p->ip_p)
            {
                case IPPROTO_TCP:
                    if(IS_REGISTERED(HANDLER_TCP))
                    {
                        (*(_handlers[HANDLER_TCP]))(network_p);
                    }
                    break;
                case IPPROTO_UDP:
                    if(IS_REGISTERED(HANDLER_UDP))
                    {
                        (*(_handlers[HANDLER_UDP]))(network_p);
                    }
                    break;
                case IPPROTO_ICMP:
                    if(IS_REGISTERED(HANDLER_ICMP))
                    {
                        (*(_handlers[HANDLER_ICMP]))(network_p);
                    }
                    break;
                case IPPROTO_IGMP:
                    if(IS_REGISTERED(HANDLER_IGMP))
                    {
                        (*(_handlers[HANDLER_IGMP]))(network_p);
                    }
                    break;
                default:
                    break;
            }
            break;
        case PROTO_ARP:
            if(IS_REGISTERED(HANDLER_ARP))
            {
                (*(_handlers[HANDLER_ARP]))(network_p);
            }
            break;
        case PROTO_IPV6:
            if(IS_REGISTERED(HANDLER_IPV6))
            {
                (*(_handlers[HANDLER_IPV6]))(network_p);
            }
            break;
        case PROTO_PPPDS:
            if(IS_REGISTERED(HANDLER_PPPDS))
            {
                (*(_handlers[HANDLER_PPPDS]))(network_p);
            }
            break;
        case PROTO_PPPSS:
            if(IS_REGISTERED(HANDLER_PPPSS))
            {
                (*(_handlers[HANDLER_PPPSS]))(network_p);
            }
            break;
        case PROTO_FCTRL:
            if(IS_REGISTERED(HANDLER_FCTRL))
            {
                (*(_handlers[HANDLER_FCTRL]))(network_p);
            }
            break;
        default:
            break;
            // default action
    }
}


