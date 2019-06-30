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
// pcap writer stuff
//-------------------------------------------------------------------------

#include <iostream>
using namespace std;

#include <math.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include "pcap_writer.h"

#define MAX_SNAP 65535

class PcapWriterImpl {
public:
    pcap_dumper_t* pcap;
    unsigned numPkts;
    struct timeval ptime;
    struct timeval last;
};

//-------------------------------------------------------------------------
// this is a bit of a hack but covers the most common cases.
//
// * the root proto determines the dlt which is stored in
//   the file so changing that on the fly will cause broken
//   pcaps.
// 
// * pcap doesn't like DLT_IPV? in a file, giving:
//   "link-layer type -1 isn't supported in savefiles"
//   so we return raw instead.

static int GetDataLinkType (const char* proto) {
    if ( !strncasecmp(proto, "eth", 3) )
        return DLT_EN10MB;

#if 0
    if ( !strncasecmp(proto, "ip4", 3) )
        return DLT_IPV4;

    if ( !strncasecmp(proto, "ip6", 3) )
        return DLT_IPV6;
#endif

    return DLT_RAW;
}

//-------------------------------------------------------------------------

PcapWriter::PcapWriter (
    const char* name, const char* root, uint32_t max) {
    my = new PcapWriterImpl;

    if ( !name )
        return;

    if ( !max ) max = MAX_SNAP;
    int dlt = GetDataLinkType(root);

    pcap_t* dummy = pcap_open_dead(dlt, max);
    my->pcap = dummy ? pcap_dump_open(dummy, name) : nullptr;

    if ( !my->pcap ) {
        cerr << "Error - can't open pcap: ";
        cerr << pcap_geterr(dummy) << endl;
    }
    pcap_close(dummy);
    my->numPkts = 0;

    //memset (&my->ptime, 0, sizeof(my->ptime));
    gettimeofday(&my->ptime, nullptr);
    my->last = my->ptime;
}

PcapWriter::~PcapWriter () {
    if ( my->pcap ) pcap_dump_close(my->pcap);
    cout << my->numPkts << " packets written" << endl;
    delete my;
}

bool PcapWriter::Ok () {
    return my->pcap != nullptr;
}

void PcapWriter::operator<< (const Packet& p) {
    if ( !my->pcap ) return;

    struct pcap_pkthdr h;

    h.len = p.Length();
    h.caplen = (p.snap && h.len > p.snap) ? p.snap : h.len;

    struct timeval now;
    //memset (&now, 0, sizeof(now));
    gettimeofday(&now, nullptr);

    long ds, du;

    if ( p.late ) {
        ds = (long)p.late;
        du = round((p.late-ds) * 1e6);

    } else {
        ds = now.tv_sec - my->last.tv_sec;
        du = now.tv_usec - my->last.tv_usec;

        if ( ds < 0 ) ds = 0;
        if ( du < 0 ) du += 1000000;

    }
    my->ptime.tv_sec += ds;
    my->ptime.tv_usec += du;

    if ( my->ptime.tv_usec > 1000000 ) {
        my->ptime.tv_usec -= 1000000;
        my->ptime.tv_sec++;
    }
    h.ts.tv_sec = my->ptime.tv_sec;
    h.ts.tv_usec = my->ptime.tv_usec;

    pcap_dump((u_char*)my->pcap, &h, p.Data());

    my->numPkts++;
    my->last = now;
}

