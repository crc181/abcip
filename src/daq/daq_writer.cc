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

#include <daq_common.h>

#include "daq_writer.h"

class DaqWriterImpl {
public:
    struct timeval start;
    DAQ_Stats_t stats;

    DAQ_Analysis_Func_t func;
    void* user;
};

DaqWriter::DaqWriter () {
    my = new DaqWriterImpl;

    my->func = NULL;
    my->user = NULL;

    memset (&my->start, 0, sizeof(my->start));
    gettimeofday(&my->start, NULL);

    ResetStats();
}

DaqWriter::~DaqWriter () {
    delete my;
}

void DaqWriter::GetStats (DAQ_Stats_t* s) {
    *s = my->stats;
}

void DaqWriter::ResetStats () {
    memset(&my->stats, 0, sizeof(my->stats));
}

void DaqWriter::SetCallback (DAQ_Analysis_Func_t cb, void* pv) {
    my->func = cb;
    my->user = pv;
}

void DaqWriter::operator<< (const Packet& p) {
    DAQ_PktHdr_t h = p.daqhdr;

    h.pktlen = p.Length();
    h.caplen = (p.snap && h.pktlen > p.snap) ? p.snap : h.pktlen;

    if ( p.late ) {
        h.ts.tv_sec = my->start.tv_sec;
        h.ts.tv_usec = my->start.tv_usec;

        uint32_t us = (uint32_t)p.late;
        us = round((p.late-us) * 1e6);

        my->start.tv_sec += p.late;
        my->start.tv_usec += us;

        if ( h.ts.tv_usec > 1000000 ) {
            h.ts.tv_usec -= 1000000;
            h.ts.tv_sec++;
        }
    } else {
        struct timeval t;
        memset (&t, 0, sizeof(t));
        gettimeofday(&t, NULL);

        h.ts.tv_sec = t.tv_sec;
        h.ts.tv_usec = t.tv_usec;
    }

    if ( !my->func )
        return;

    DAQ_Verdict v = my->func(my->user, &h, p.Data());

    if ( v < MAX_DAQ_VERDICT ) { 
        my->stats.verdicts[v]++;
        my->stats.packets_received++;
    }
}

