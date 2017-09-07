//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2011-2013 Charles R. Combs
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
#include <string>
using namespace std;

#include "cake.h"
#include "phy.h"

static const char* s_type = "phy";

struct PhyImpl {
    string* buf;
    unsigned* order;
    unsigned max, nIn, nOut;

    uint32_t snap;
    float late;

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
    buf = NULL;
    order = NULL;
    max = nIn = nOut = 0;
}

PhyProtocol::PhyProtocol () : Protocol(s_type) {
    my = new PhyImpl;
    my->buf = NULL;
    my->order = NULL;
    my->max = my->nIn = my->nOut = 0;
    my->snap = 0;
    my->late = 0.0;
}

PhyProtocol::~PhyProtocol () {
    if ( my->buf ) delete[] my->buf;
    if ( my->order ) delete[] my->order;
    delete my;
}

bool PhyProtocol::Bind (const string&) {
    return true;
}

void PhyProtocol::Fetch (Cake& cake, bool) {
    if ( cake.IsSet("seed") )
        srand(cake.GetValue("seed", 1));

    my->snap = cake.GetValue("snap", my->snap);
    my->late = cake.GetReal("sec", my->late);
}

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
    { FT_PKT, "drop", "b", "don't log packet" },
    { FT_PKT, "rev", "u32", "output packets in reverse order" },
    { FT_PKT, "perm", "u32", "randomly permute packets" },
    { FT_PKT, "dt", "r32", "set time delta for this packet" },
    { FT_MAX, NULL, NULL, NULL }
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

