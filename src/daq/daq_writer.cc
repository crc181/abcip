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

#include <math.h>
#include <string.h>

#include <vector>

#include <daq_common.h>

#include "daq_writer.h"

using namespace std;

struct DaqWriterPktDesc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
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
    DaqWriterImpl(uint32_t pool_size, uint32_t snaplen, bool real_time);
    ~DaqWriterImpl();

    struct timeval last;
    struct timeval interval = { 0, 1 };

    uint32_t snap;
    DaqWriterMsgPool pool = { };
    const DAQ_Msg_t** msg_vector = nullptr;
    unsigned msg_count = 0;
};

DaqWriterImpl::DaqWriterImpl(uint32_t pool_size, uint32_t snaplen, bool real_time)
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
        msg->priv = desc;
        pool.freelist.push_back(desc);
        pool.info.mem_size += snap;
        pool.info.size++;
    }
    pool.info.available = pool.info.size;

    if (real_time)
        gettimeofday(&last, NULL);
    else
        last = { 946684800, 0 }; // Defaults to Y2K
}

DaqWriterImpl::~DaqWriterImpl()
{
    while (pool.info.size > 0)
        delete[] pool.pool[--pool.info.size].msg.data;
    delete[] pool.pool;
}

DaqWriter::DaqWriter(uint32_t pool_size, uint32_t snaplen, bool real_time)
{
    impl = new DaqWriterImpl(pool_size, snaplen, real_time);
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
    DaqWriterPktDesc* desc = (DaqWriterPktDesc*) msg->priv;
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
    desc->pkthdr = p.daqhdr;

    desc->pkthdr.pktlen = p.Length();
    uint32_t data_len = (p.snap && desc->pkthdr.pktlen > p.snap) ? p.snap : desc->pkthdr.pktlen;
    data_len = (data_len > impl->snap) ? impl->snap : data_len;
    desc->msg.data_len = data_len;
    memcpy(desc->msg.data, p.Data(), desc->msg.data_len);

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

    impl->msg_vector[impl->msg_count++] = &desc->msg;

    impl->last = desc->pkthdr.ts;
}

