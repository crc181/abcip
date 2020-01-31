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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "phy.h"

#include <arpa/inet.h>

#include <cstring>

#include "cake.h"
#include "field.h"
#include "packet.h"
#include "pimp.h"

using namespace std;

static const char* s_type = "phy";

struct PhyImpl {
    string* buf = nullptr;
    unsigned* order = nullptr;
    unsigned max = 0;
    unsigned nIn = 0;
    unsigned nOut = 0;

    // Various bits of additional information about the Packet that are not
    // part of the generated packet data itself.  These match up to those in
    // the Packet structure.
    uint32_t snap = 0;
    float late = 0.0;
    int32_t ingress_intf_id = -1;
    int32_t ingress_intf_group = -1;
    int32_t egress_intf_id = -1;
    int32_t egress_intf_group = -1;
    uint32_t flow_id = 0;
    bool flow_id_set = false;
    uint32_t address_space_id = 0;
    uint32_t real_src_ip[4];
    uint16_t real_src_family = AF_UNSPEC;
    uint16_t real_src_port = 0;
    uint32_t real_dst_ip[4];
    uint16_t real_dst_family = AF_UNSPEC;
    uint16_t real_dst_port = 0;

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
    buf = nullptr;
    delete[] order;
    order = nullptr;
    max = nIn = nOut = 0;
}

PhyProtocol::PhyProtocol () : Protocol(s_type) {
    my = new PhyImpl;
}

PhyProtocol::~PhyProtocol () {
    if ( my->buf )
        delete[] my->buf;
    if ( my->order )
        delete[] my->order;
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

    if (cake.IsSet("fid"))
    {
        my->flow_id = cake.GetValue("fid", my->flow_id);
        my->flow_id_set = true;
    }

    my->address_space_id = cake.GetValue("as", my->address_space_id);

    if (a2b)
        FetchA2B(cake);
    else
        FetchB2A(cake);
}

void PhyProtocol::FetchA2B (Cake& cake)
{
    my->ingress_intf_id = cake.GetValue("a.if", my->ingress_intf_id);
    my->ingress_intf_group = cake.GetValue("a.gr", my->ingress_intf_group);
    my->egress_intf_id = cake.GetValue("b.if", my->egress_intf_id);
    my->egress_intf_group = cake.GetValue("b.gr", my->egress_intf_group);

    if (cake.IsSet("a.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("a.rip"), &my->real_src_ip);
        my->real_src_family = AF_INET;
    }
    else if (cake.IsSet("a.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("a.rip6"), &my->real_src_ip);
        my->real_src_family = AF_INET6;
    }
    my->real_src_port = htons(cake.GetValue("a.rpt", my->real_src_port));

    if (cake.IsSet("b.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("b.rip"), &my->real_dst_ip);
        my->real_dst_family = AF_INET;
    }
    else if (cake.IsSet("b.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("b.rip6"), &my->real_dst_ip);
        my->real_dst_family = AF_INET6;
    }
    my->real_dst_port = htons(cake.GetValue("b.rpt", my->real_dst_port));
}

// Swap directional attributes for the B-to-A case.
void PhyProtocol::FetchB2A (Cake& cake)
{
    my->ingress_intf_id = cake.GetValue("b.if", my->ingress_intf_id);
    my->ingress_intf_group = cake.GetValue("b.gr", my->ingress_intf_group);
    my->egress_intf_id = cake.GetValue("a.if", my->egress_intf_id);
    my->egress_intf_group = cake.GetValue("a.gr", my->egress_intf_group);

    if (cake.IsSet("b.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("b.rip"), &my->real_src_ip);
        my->real_src_family = AF_INET;
    }
    else if (cake.IsSet("b.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("b.rip6"), &my->real_src_ip);
        my->real_src_family = AF_INET6;
    }
    my->real_src_port = htons(cake.GetValue("b.rpt", my->real_src_port));

    if (cake.IsSet("a.rip"))
    {
        inet_pton(AF_INET, cake.GetCValue("a.rip"), &my->real_dst_ip);
        my->real_dst_family = AF_INET;
    }
    else if (cake.IsSet("a.rip6"))
    {
        inet_pton(AF_INET6, cake.GetCValue("a.rip6"), &my->real_dst_ip);
        my->real_dst_family = AF_INET6;
    }
    my->real_dst_port = htons(cake.GetValue("a.rpt", my->real_dst_port));
}

const uint8_t* PhyProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    // Set all of the esoteric Packet attributes
    p.drop = p.cake.IsSet("drop");
    p.user_annotation = p.cake.GetValue("user");
    p.snap = my->snap;
    p.late = p.cake.GetReal("dt", my->late);
    p.ingress_intf_id = my->ingress_intf_id;
    p.ingress_intf_group = my->ingress_intf_group;
    p.egress_intf_id = my->egress_intf_id;
    p.egress_intf_group = my->egress_intf_group;
    p.flow_id = my->flow_id;
    p.flow_id_set = my->flow_id_set;
    p.address_space_id = my->address_space_id;
    memcpy(&p.real_src_ip, &my->real_src_ip, sizeof(p.real_src_ip));
    p.real_src_family = my->real_src_family;
    p.real_src_port = my->real_src_port;
    memcpy(&p.real_dst_ip, &my->real_dst_ip, sizeof(p.real_dst_ip));
    p.real_dst_family = my->real_dst_family;
    p.real_dst_port = my->real_dst_port;

    if (my->max)
    {
        if (my->nOut == my->max)
            my->Clear();
        else if (!my->nOut)
            p.drop = true;
    }

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
        my->buf[my->nIn++].assign((const char*)p.Data(), p.Length());

    if ( HasPayload() ) {
        string& buf = my->buf[my->order[my->nOut++]];
        len = buf.length();
        return (const uint8_t*)buf.data();
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
    { FT_PKT, "user", "s*", "user-defined annotation" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class PhyPimp : public Pimp {
public:
    PhyPimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new PhyProtocol();
    }

    void HelpBind(ostream&) override;
};

void PhyPimp::HelpBind (ostream& out) {
    out << Type() << " -> any" << endl;
}

Pimp* PhyProtocol::GetPimp () { return new PhyPimp; }

