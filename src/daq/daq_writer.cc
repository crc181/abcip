//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2017 Charles R. Combs
//
// Abcip is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your
// option) any later version.
// 
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//--------------------------------------------------------------------- EOL

//-------------------------------------------------------------------------
// daq writer stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "daq_writer.h"

#include <daq_common.h>

#include <cmath>
#include <cstring>
#include <vector>

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

using namespace std;

struct DaqWriterPktDesc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    DAQ_NAPTInfo_t napti;
};

struct DaqWriterMsgPool
{
    DaqWriterPktDesc* pool;
    vector<DaqWriterPktDesc*> freelist;
    DAQ_MsgPoolInfo_t info;
};

class DaqWriterImpl
{
public:
    DaqWriterImpl(DAQ_ModuleInstance_h modinst, uint32_t pool_size, uint32_t snaplen, bool real_time);
    ~DaqWriterImpl();

    struct timeval last;
    struct timeval interval = { 0, 1 };

    uint32_t snap;
    DaqWriterMsgPool pool = { };
    const DAQ_Msg_t** msg_vector = nullptr;
    unsigned msg_count = 0;
};

DaqWriterImpl::DaqWriterImpl(DAQ_ModuleInstance_h modinst, uint32_t pool_size, uint32_t snaplen, bool real_time)
{
    snap = snaplen;

    pool.pool = new DaqWriterPktDesc[pool_size]();
    pool.info.mem_size = sizeof(DaqWriterPktDesc) * pool_size;
    for (uint32_t i = 0; i < pool_size; i++)
    {
        DaqWriterPktDesc* desc = &pool.pool[i];
        DAQ_Msg_t* msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->data = new uint8_t[snap];
        msg->owner = modinst;
        msg->priv = desc;
        pool.freelist.push_back(desc);
        pool.info.mem_size += snap;
        pool.info.size++;
    }
    pool.info.available = pool.info.size;

    if (real_time)
        gettimeofday(&last, nullptr);
    else
        last = { 946684800, 0 }; // Defaults to Y2K
}

DaqWriterImpl::~DaqWriterImpl()
{
    while (pool.info.size > 0)
        delete[] pool.pool[--pool.info.size].msg.data;
    delete[] pool.pool;
}

DaqWriter::DaqWriter(DAQ_ModuleInstance_h modinst, uint32_t pool_size, uint32_t snaplen, bool real_time)
{
    impl = new DaqWriterImpl(modinst, pool_size, snaplen, real_time);
}

DaqWriter::~DaqWriter()
{
    delete impl;
}

void DaqWriter::SetMsgVector(const DAQ_Msg_t* msgs[])
{
    impl->msg_count = 0;
    impl->msg_vector = msgs;
}

unsigned DaqWriter::GetMsgCount()
{
    return impl->msg_count;
}

void DaqWriter::ReleaseMsg(const DAQ_Msg_t* msg)
{
    DaqWriterPktDesc* desc = static_cast<DaqWriterPktDesc*>(msg->priv);
    impl->pool.freelist.push_back(desc);
}

void DaqWriter::GetMsgPoolInfo(DAQ_MsgPoolInfo_t* info)
{
    *info = impl->pool.info;
}

void DaqWriter::operator<<(const Packet& p)
{
    DaqWriterPktDesc* desc = impl->pool.freelist.back();
    impl->pool.freelist.pop_back();

    /* Set up the DAQ packet header. */
    DAQ_PktHdr_t* hdr = &desc->pkthdr;
    // Per-packet override of the timing interval
    if (p.late)
    {
        struct timeval increment;
        increment.tv_sec = static_cast<time_t>(p.late);
        increment.tv_usec = round((p.late - increment.tv_sec) * 1e6);
        timeradd(&impl->last, &increment, &desc->pkthdr.ts);
    }
    else
        timeradd(&impl->last, &impl->interval, &desc->pkthdr.ts);
    hdr->pktlen = p.Length();
    hdr->ingress_index = (p.ingress_intf_id >= 0) ? p.ingress_intf_id : DAQ_PKTHDR_UNKNOWN;
    hdr->egress_index = (p.egress_intf_id >= 0) ? p.egress_intf_id : DAQ_PKTHDR_UNKNOWN;
    hdr->ingress_group = (p.ingress_intf_group >= 0) ? p.ingress_intf_group : DAQ_PKTHDR_UNKNOWN;
    hdr->egress_group = (p.egress_intf_group >= 0) ? p.egress_intf_group : DAQ_PKTHDR_UNKNOWN;
    hdr->opaque = 0;
    hdr->flow_id = p.flow_id;
    hdr->flags = 0;
    if (p.flow_id_set)
        hdr->flags |= DAQ_PKT_FLAG_FLOWID_IS_VALID;
    hdr->address_space_id = p.address_space_id;

    /* Set up the DAQ message, copying the packet data. */
    DAQ_Msg_t* msg = &desc->msg;
    uint32_t data_len = (p.snap && hdr->pktlen > p.snap) ? p.snap : hdr->pktlen;
    data_len = (data_len > impl->snap) ? impl->snap : data_len;
    memcpy(msg->data, p.Data(), data_len);
    msg->data_len = data_len;
    /* If the "real" address info is present, fill out and provide the NAPT Info metadata. */
    if (p.real_src_family != AF_UNSPEC && p.real_dst_family != AF_UNSPEC)
    {
        DAQ_NAPTInfo_t* napti = &desc->napti;
        napti->flags = 0;

        if (p.real_src_family == AF_INET6)
        {
            memcpy(&napti->src_addr.s6_addr32, &p.real_src_ip, sizeof(napti->src_addr.s6_addr32));
            napti->flags |= DAQ_NAPT_INFO_FLAG_SIP_V6;
        }
        else
            napti->src_addr.s6_addr32[0] = p.real_src_ip[0];
        napti->src_port = p.real_src_port;

        if (p.real_dst_family == AF_INET6)
        {
            memcpy(&napti->dst_addr.s6_addr32, &p.real_dst_ip, sizeof(napti->dst_addr.s6_addr32));
            napti->flags |= DAQ_NAPT_INFO_FLAG_DIP_V6;
        }
        else
            napti->dst_addr.s6_addr32[0] = p.real_dst_ip[0];
        napti->dst_port = p.real_dst_port;
        msg->meta[DAQ_PKT_META_NAPT_INFO] = napti;
    }
    else
        msg->meta[DAQ_PKT_META_NAPT_INFO] = nullptr;

    impl->msg_vector[impl->msg_count++] = &desc->msg;

    impl->last = desc->pkthdr.ts;
}

