#ifndef _BD_SNIFFER_BASE_H
#define _BD_SNIFFER_BASE_H

#include <string>

#include "bd_pcap_session.h"
#include "pcap/pcap.h"

#define PROTO_IPV4  0x0800
#define PROTO_IPV6  0x86DD
#define PROTO_ARP   0x0806
#define PROTO_IPX   0x8137 /*novell IPX*/
#define PROTO_IPX2  0x8138 /*novell IPX*/
#define PROTO_PPPDS 0x8863 /*PPPoE discovery stage*/
#define PROTO_PPPSS 0x8864 /*PPPoE session stage*/
#define PROTO_FCTRL 0x8808 /*flow control*/

//#define IPPROTO_ICMP  1
//#define IPPROTO_IGMP  2
//#define IPPROTO_TCP   6
//#define IPPROTO_UDP   17

typedef void (*pkt_handler_t)(const u_char *packet);
typedef bpf_u_int32 sniffer_addr_t;

enum handler_type_e
{
    HANDLER_IPV4,
    HANDLER_IPV6,
    HANDLER_ARP,
    HANDLER_PPPDS,
    HANDLER_PPPSS,
    HANDLER_FCTRL,
    HANDLER_TCP,
    HANDLER_UDP,
    HANDLER_ICMP,
    HANDLER_IGMP,
    HANDLER_TYPE_MAX
};

enum result_code_e
{
    SNIFFER_OK,
    SNIFFER_ERR,    // for common error
    SNIFFER_ERR_HANDLER,
    SNIFFER_ERR_INIT,

    /* pcap-related errors*/
    SNIFFER_ERR_PCAP,
    SNIFFER_ERR_PCAP_DEVICE,
    SNIFFER_ERR_PCAP_FILTER
};

struct ethernet_header
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    union{
        uint16_t type;
        struct 
        {
            uint16_t size;
            uint8_t dsap;
            uint8_t ssap;
            uint8_t ctrl;
        }llc_hdr;
    }v; 
};

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	//struct	in_addr ip_src,ip_dst;	/* source and dest address */
    u_int   ip_src, id_dst;
};

//typedef struct 
//{
//
//        uint32_t promisc;             /* set the device to promiscuous mode or not. default to 0 */
//        uint32_t link_type;           /* pcap-defined linktype, provided by pcap_datalink*/
//        uint32_t link_type_offset;    /* offset to information in link-layer header giving pkt type */ 
//        uint32_t link_type_len;       /* offset of the beginning of the MAC-layer payload,it equals to length 
//                                          of linklayer header + any prefix preceding the link-layer header */
//        std::string device;      /* device name */ 
//        std::string filter;      /* filter string:regular expression. refer to man page of tcpdump */
//        sniffer_addr_t addr;
//        sniffer_addr_t mask;
//} pcap_info_t;

class bd_sniffer
{
    public:
        /**
         * @brief: get singleton instance
         */
        static bd_sniffer& getInstance();

        /**
         * @brief: default destructor
         */
        virtual ~bd_sniffer();

        /**
         * @brief: register packet handler
         * @param hdr: handler function address
         * @param hdr: handler index
         */
        uint8_t callbackRegister(pkt_handler_t hdr, handler_type_e idx);

        /**
         * @brief: deregister hander indexed by hdr_idx, setting to null
         * @param hdr_idx: index of the _handers array
         */
        int callbackDeregister(handler_type_e);

        /**
         * @brief: initialization for start capturing
         */
        int init(const std::string& deviceName, const std::string& filter,
                 uint32_t promisc = 0);

        /**
         * @brief: get the init status
         * @return: 1 for inited, 0 for uninited
         */
        uint8_t isInit();

        int activate();
        
#define IS_REGISTERED(e) _handlers[e]? 1:0

    private:
        /**
         * @brief: private constructor to avoid multi-instance creation
         */
        bd_sniffer();

        /**
         * @brief: callback for pcap_loop
         * Defined static for convenience of being
         * a callback function, and for the sake of
         * this, @a _handlers must be defined static
         * as well.
         * @param args User-defined args
         * @param header Pcap header
         * @param packet Pointer to captured packet
         */
        static void _l(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet);

        bd_pcap_session *_sess;
        static pkt_handler_t _handlers[HANDLER_TYPE_MAX]; /* registered handler for processing captured packets */
        uint8_t _init_flag;

        // singleton obj
        static bd_sniffer *_instance;
};

#endif
