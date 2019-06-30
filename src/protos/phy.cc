//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2011-2017 Charles R. Combs
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
// physical layer stuff
//-------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>
#include <string>

#include "cake.h"
#include "phy.h"

using namespace std;

static const char* s_type = "phy";

struct PhyImpl {
    string* buf;
    unsigned* order;
    unsigned max, nIn, nOut;

    uint32_t snap;
    float late;

#ifdef HAVE_DAQ
    DAQ_PktHdr_t daqhdr;
#endif

    void Reverse(unsigned);
    void Permute(unsigned);
    void Clear();
};

void PhyImpl::Reverse (unsigned n) {
    buf = new string[n];
    order = new unsigned[n];

    max = n;
    nIn = nOut = 0;

    for ( unsigned i = 0; i < n; i++ )
        order[i] = n - i - 1;
}

void PhyImpl::Permute (unsigned n) {
    buf = new string[n];
    order = new unsigned[n];

    max = n;
    nIn = nOut = 0;

    unsigned i;

    for ( i = 0; i < n; i++ )
        order[i] = i;

    // fisher-yates
    for ( i = n-1; i > 0; i-- ) {
        // maybe lame on the rand-o-meter but
        // more than sufficient for our purposes
        unsigned j = rand() % i;

        unsigned tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
}

void PhyImpl::Clear () {
    delete[] buf;
    delete[] order;
    buf = nullptr;
    order = nullptr;
    max = nIn = nOut = 0;
}

PhyProtocol::PhyProtocol () : Protocol(s_type) {
    my = new PhyImpl;
    my->buf = nullptr;
    my->order = nullptr;
    my->max = my->nIn = my->nOut = 0;
    my->snap = 0;
    my->late = 0.0;

#ifdef HAVE_DAQ
    memset(&my->daqhdr, 0, sizeof(my->daqhdr));

    my->daqhdr.ingress_index = DAQ_PKTHDR_UNKNOWN;
    my->daqhdr.egress_index = DAQ_PKTHDR_UNKNOWN;
    my->daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
    my->daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
#endif
}

PhyProtocol::~PhyProtocol () {
    if ( my->buf ) delete[] my->buf;
    if ( my->order ) delete[] my->order;
    delete my;
}

bool PhyProtocol::Bind (const string&) {
    return true;
}

void PhyProtocol::Fetch (Cake& cake, bool a2b) {
    if ( cake.IsSet("seed") )
        srand(cake.GetValue("seed", 1));

    my->snap = cake.GetValue("snap", my->snap);
    my->late = cake.GetReal("sec", my->late);

#ifdef HAVE_DAQ
    if (cake.IsSet("fid"))
    {
        my->daqhdr.flow_id = cake.GetValue("fid", my->daqhdr.flow_id);
        my->daqhdr.flags |= DAQ_PKT_FLAG_FLOWID_IS_VALID;
    }

    my->daqhdr.address_space_id = cake.GetValue("as", my->daqhdr.address_space_id);

    if (a2b)
        FetchA2B(cake);
    else
        FetchB2A(cake);
#endif
}

#ifdef HAVE_DAQ
void PhyProtocol::FetchA2B (Cake& cake)
{
    my->daqhdr.ingress_index = cake.GetValue("a.if", my->daqhdr.ingress_index);
    my->daqhdr.egress_index = cake.GetValue("b.if", my->daqhdr.egress_index);
    my->daqhdr.ingress_group = cake.GetValue("a.gr", my->daqhdr.ingress_group);
    my->daqhdr.egress_group = cake.GetValue("b.gr", my->daqhdr.egress_group);

    if (cake.IsSet("a.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("a.rip"), &my->daqhdr.real_sIP);
        my->daqhdr.flags |= DAQ_PKT_FLAG_REAL_ADDRESSES;
    }
    if (cake.IsSet("b.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("b.rip"), &my->daqhdr.real_dIP);
        my->daqhdr.flags |= DAQ_PKT_FLAG_REAL_ADDRESSES;
    }
    if (cake.IsSet("a.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("a.rip6"), &my->daqhdr.real_sIP);
        my->daqhdr.flags |= (DAQ_PKT_FLAG_REAL_ADDRESSES | DAQ_PKT_FLAG_REAL_SIP_V6);
    }
    if (cake.IsSet("b.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("b.rip6"), &my->daqhdr.real_dIP);
        my->daqhdr.flags |= (DAQ_PKT_FLAG_REAL_ADDRESSES | DAQ_PKT_FLAG_REAL_SIP_V6);
    }
    my->daqhdr.n_real_sPort = htons(cake.GetValue("a.rpt", my->daqhdr.n_real_sPort));
    my->daqhdr.n_real_dPort = htons(cake.GetValue("b.rpt", my->daqhdr.n_real_dPort));
}

// Swap directional DAQ components for the B-to-A case.
void PhyProtocol::FetchB2A (Cake& cake)
{
    my->daqhdr.ingress_index = cake.GetValue("b.if", my->daqhdr.ingress_index);
    my->daqhdr.egress_index = cake.GetValue("a.if", my->daqhdr.egress_index);
    my->daqhdr.ingress_group = cake.GetValue("b.gr", my->daqhdr.ingress_group);
    my->daqhdr.egress_group = cake.GetValue("a.gr", my->daqhdr.egress_group);
     if (cake.IsSet("b.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("b.rip"), &my->daqhdr.real_sIP);
        my->daqhdr.flags |= DAQ_PKT_FLAG_REAL_ADDRESSES;
    }
    if (cake.IsSet("a.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("a.rip"), &my->daqhdr.real_dIP);
        my->daqhdr.flags |= DAQ_PKT_FLAG_REAL_ADDRESSES;
    }
    if (cake.IsSet("b.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("b.rip6"), &my->daqhdr.real_sIP);
        my->daqhdr.flags |= (DAQ_PKT_FLAG_REAL_ADDRESSES | DAQ_PKT_FLAG_REAL_SIP_V6);
    }
    if (cake.IsSet("a.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("a.rip6"), &my->daqhdr.real_dIP);
        my->daqhdr.flags |= (DAQ_PKT_FLAG_REAL_ADDRESSES | DAQ_PKT_FLAG_REAL_SIP_V6);
    }
    my->daqhdr.n_real_sPort = htons(cake.GetValue("b.rpt", my->daqhdr.n_real_sPort));
    my->daqhdr.n_real_dPort = htons(cake.GetValue("a.rpt", my->daqhdr.n_real_dPort));
}
#endif

const uint8_t* PhyProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    p.drop = p.cake.IsSet("drop");

    p.snap = my->snap;
    p.late = p.cake.GetReal("dt", my->late);

    if ( my->max && my->nOut == my->max )
        my->Clear();

    if ( my->max && !my->nOut )
        p.drop = true;

#ifdef HAVE_DAQ
    p.daqhdr = my->daqhdr;
#endif

    return Protocol::GetHeader(p, len);
}

const uint8_t* PhyProtocol::GetPayload (
    const Packet& p, uint32_t& len
) {
    if ( !my->max ) {
        unsigned rev = p.cake.GetValue("rev", 0);
        unsigned perm = p.cake.GetValue("perm", 0);

        if ( rev ) my->Reverse(rev);
        else if ( perm ) my->Permute(perm);

        // otherwise this repeats and, absent 
        // a flush at the end, we lose packets
        p.cake.Clear("rev");
        p.cake.Clear("perm");
    }
    if ( my->max && (my->nIn < my->max) )
        my->buf[my->nIn++].assign((char*)p.Data(), p.Length());

    if ( HasPayload() ) {
        string& buf = my->buf[my->order[my->nOut++]];
        len = buf.length();
        return (uint8_t*)buf.data();
    }    
    return Protocol::GetPayload(p, len);
}

bool PhyProtocol::HasPayload () {
    return ( my->max &&
            (my->nIn == my->max) &&
            (my->nOut < my->max) );
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "snap", "u32", "set snap length" },
    { FT_CFG, "seed", "u32", "set perm seed" },
    { FT_CFG, "sec", "r32", "set latency seconds" },

    { FT_CFG, "a.if", "i32", "set host a interface" },
    { FT_CFG, "b.if", "i32", "set host b interface" },
    { FT_CFG, "a.gr", "i32", "set host a interface group" },
    { FT_CFG, "b.gr", "i32", "set host b interface group" },
    { FT_CFG, "a.rip", "a4", "set host a real address" },
    { FT_CFG, "b.rip", "a4", "set host b real address" },
    { FT_CFG, "a.rip6", "a16", "set host a real v6 address" },
    { FT_CFG, "b.rip6", "a16", "set host b real v6 address" },
    { FT_CFG, "a.rpt", "u16", "set host a real port" },
    { FT_CFG, "b.rpt", "u16", "set host b real port" },
    { FT_CFG, "fid", "u32", "set flow id" },
    { FT_CFG, "as", "u16", "set address space id" },

    { FT_PKT, "drop", "b", "don't log packet" },
    { FT_PKT, "rev", "u32", "output packets in reverse order" },
    { FT_PKT, "perm", "u32", "randomly permute packets" },
    { FT_PKT, "dt", "r32", "set time delta for this packet" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class PhyPimp : public Pimp {
public:
    PhyPimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new PhyProtocol();
    };

    void HelpBind(ostream&);
};

void PhyPimp::HelpBind (ostream& out) {
    out << Type() << " -> any" << endl;
}

Pimp* PhyProtocol::GetPimp () { return new PhyPimp; }

