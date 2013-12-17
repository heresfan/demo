#include "bd_pcap_session.h"
#include "pcap/pcap.h"

static char errbuf[PCAP_ERRBUF_SIZE + 1];

link_info_t datalink_table[] = {
    {DLT_NULL, 0, 4},
    {DLT_EN10MB, 12, 14},	
    {DLT_EN3MB, -1, -1},	
    {DLT_AX25, -1, -1},	
    {DLT_PRONET, -1, -1},	
    {DLT_CHAOS, -1, -1},	
    {DLT_IEEE802, 14, 14},	
    {DLT_ARCNET, 2, 6},	
    {DLT_SLIP, -1, 16},	
    {DLT_PPP, 2, 4},	
    {DLT_FDDI, 13, 13}	
};

bd_pcap_session::bd_pcap_session()
{
}

bd_pcap_session::bd_pcap_session(
        std::string dev, std::string filter,
        uint32_t snap_len, uint32_t promisc_mode, 
        uint32_t timeout):
    /* initialization list */
    _dev(dev), _filter(filter), _status(0)/*assume that we want a live session*/,
    _snap_len(snap_len), _promisc_mode(promisc_mode), _timeout(timeout), _handle(NULL)
{
    /* get session handler:
     * if the device name is not provided or incorrect
     * we open a session that is tagged as dead by 
     * setting flag to 0
     */
    if(_dev.empty() ||
            (_handle = pcap_open_live(_dev.c_str(), _snap_len,
                                      _promisc_mode, _timeout, errbuf)) == NULL)
    {
        _handle = pcap_open_dead(DLT_EN10MB, 1/*snap len*/);
    }
    else
    {
        _status = 1; // we have opened up a live session

        // = compile a filter if existing
        if(!filter.empty())
        {
            struct bpf_program fp;
            uint32_t mask, netp;
            if(!pcap_lookupnet(_dev.c_str(), &netp, &mask, errbuf))
            {
                if(!pcap_compile(_handle, &fp, _filter.c_str(), 0/*not optimize*/, netp))
                {
                    pcap_setfilter(_handle, &fp);
                }
            }
        }
    }

    // = init linktype info
    _link_info.link_type = pcap_datalink(_handle);
}

bd_pcap_session::~bd_pcap_session()
{
    if(_handle)
    {
        pcap_breakloop(_handle);
        pcap_close(_handle);
    }
}

uint32_t bd_pcap_session::getLinktype(const std::string& name) const
{
    return pcap_datalink_name_to_val(name.c_str());
}

std::string bd_pcap_session::getLinktypeName(uint32_t linktype) const
{
    return pcap_datalink_val_to_name(linktype);
}

std::string bd_pcap_session::getDeviceName() const
{
    return _dev;
}

const std::string& bd_pcap_session::getFilter() const
{
    return _filter;
}

void bd_pcap_session::setDeviceName(const std::string &name)
{
    if(name != _dev)
    {
        _dev = name;
        _recreate();
    }
}

void bd_pcap_session::setFilter(const std::string &fil)
{
    if(_filter != fil)
    {
        struct bpf_program fp;
        _filter = fil;
        uint32_t netp, mask;
        if(_status == 1 && pcap_lookupnet(_dev.c_str(), &netp, &mask, errbuf))
        {
            if(!pcap_compile(_handle, &fp, _filter.c_str(), 0, netp))
            {
                pcap_setfilter(_handle, &fp);
            }
        }
    }
}

uint32_t bd_pcap_session::isLive()
{
    return _status;
}

uint32_t bd_pcap_session::startCap(pcap_handler callback, u_char *args)
{
    return pcap_loop(_handle, -1, callback, args);
}

void bd_pcap_session::_recreate()
{
    // close the previous session
    if(_handle)
    {
        pcap_breakloop(_handle);
        pcap_close(_handle);
        _handle = NULL;
    }

    // recreate a new session with _dev and _filter 
    // that maybe have been updated
    if(_dev.empty() ||
            (_handle = pcap_open_live(_dev.c_str(), _snap_len,
                                      _promisc_mode, _timeout, errbuf)) == NULL )
    {
        _handle = pcap_open_dead(DLT_EN10MB, 1/*snap len*/);
        _status = 0;
    }
    else
    {
        _status = 1;
    }
}


