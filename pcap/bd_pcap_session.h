/**
 * @file bd_pcap_session.h
 * @brief This file mainly define pcap session class.
 *
 * Pcap session class encapsulate implementation of libpcap
 * and provide session obj simulate a session specified with
 * device name and filter string
 *
 * @author Pigeon Lin, Bluedon co.
 * @version v1.0
 * @date 2013-11-18
 */

#ifndef _BD_PCAP_SESSION_H
#define _BD_PCAP_SESSION_H

#include <string>
#include <stdint.h>
#include "pcap.h"

typedef struct 
{
    uint32_t link_type;
    uint32_t off_linktype; /* offset to information in link-layer header giving pkt type */ 
    uint32_t off_macpl;    /* mac payload len: mac header len */
} link_info_t;

typedef pcap_handler bd_pcap_callback;



/**
 * @brief Pcap session encapsulate functions from libpcap
 *
 * This classs encapsulate implementations of libpcap
 * and provide a session simualting a capture session
 * specified with device name and filter string(optional)
 */
class bd_pcap_session
{
    public:
        /**
         * @brief constructor, the instance must be create with device name
         *         and a filter string.if device name is not supported in 
         *         the machine, the session will be a dead one.
         * @param dev        device name
         * @param filter     filter string 
         */
        bd_pcap_session(std::string dev, std::string filter, 
                uint32_t snap_len = 65535, uint32_t promisc_mode = 1, uint32_t timeout = 0);


        /**
         * @brief desctructor, free memory allocated for pcap session
         */
        virtual ~bd_pcap_session();


        /**
         * @brief get data link type
         *
         * Data link type is a field defined in link layer
         * ,for ethernet II, it's the 2 bytes field after
         * destination & source mac addresses, for 802.3 it's
         * defined in LLC layer, refer to 802.3/802.2LLC spec.
         *
         * @param name device name
         *
         * @return link layer type defined by libpcap
         */
        uint32_t getLinktype(const std::string& name) const;


        /**
         * @brief get data link type string
         *
         * @param link_type data link type int
         *
         * @return if found, the corresponding string is returned, or
         * an empty string is returned.
         */
        std::string getLinktypeName(const uint32_t link_type) const;


        /**
         * @brief get device name
         *
         * @return The corresponding device name
         */
        std::string getDeviceName() const;


        /**
         * @brief get filter string
         *
         * @return filter string
         */
        const std::string& getFilter() const;


        /**
         * @brief Set device name
         *
         * If the new device name is difference from the old one,
         * the old session handle will be free and a new session
         * will be create with the new device name
         *
         * @param name new device name
         */
        void setDeviceName(const std::string& name);


        /**
         * @brief update the filter
         *
         * If the new filter is difference from the old one,
         * the filter will be recompiled and set to the session.
         *
         * @param filter filter string
         */
        void setFilter(const std::string& filter);


        /**
         * @brief The session status:live or dead
         *
         * @return the sessions status
         */
        uint32_t isLive();

        uint32_t startCap(pcap_handler callback, u_char* args);
        
    private:
        
        /**
         * @brief default constructor:not allow creating a session
         * without device name.
         */
        bd_pcap_session();

        pcap_t *_handle; ///< session handler
        std::string _dev;
        std::string _filter;
        link_info_t _link_info;
        uint32_t _snap_len;
        uint32_t _promisc_mode;
        uint32_t _timeout;
        uint32_t _status;  // 0 for dead session, and 1 for live session

        void _recreate();
};

#endif
