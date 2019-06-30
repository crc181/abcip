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
// mpls stuff
//-------------------------------------------------------------------------

#include <ostream>

#include "cake.h"
#include "mpls.h"

// 0 and 2 are reserved labels but the actual bos
// label can be any FEC as long as the node can
// infer the network protocol.
#define MPLS_IP4  0x00000140
#define MPLS_IP6  0x00002140

// these were pulled out of thin air
#define MPLS_ETH  0x00010140
#define MPLS_MPLS 0x00003040

static const char* s_type = "mpls";

struct MplsHdr {
    uint32_t lse;
};

class MplsImpl {
public:
    MplsHdr h;
    uint8_t bos;
};

MplsProtocol::MplsProtocol () : Protocol(s_type) {
    my = new MplsImpl;
}

MplsProtocol::~MplsProtocol () {
    delete my;
}

bool MplsProtocol::Bind (const string& type) {
    if ( type == "eth" )
        my->h.lse = MPLS_ETH;

    else if ( type == "ip4" )
        my->h.lse = MPLS_IP4;

    else if ( type == "ip6" )
        my->h.lse = MPLS_IP6;

    else if ( type == "mpls" )
        my->h.lse = MPLS_MPLS;

    else 
        return false;

    my->bos = my->h.lse & 0x100 ? 1 : 0;
    return true;
}

const uint8_t* MplsProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    if ( p.cake.IsSet("lse") ) {
        my->h.lse = htonl(p.cake.GetValue("lse", 0));
        len = sizeof(my->h);
        return (uint8_t*)&my->h;
    }
    uint32_t lse = (p.cake.GetValue("lab", 0) << 12);

    lse |= ((p.cake.GetValue("tcl", 0) & 0x7) << 9);
    lse |= ((p.cake.GetValue("bos", my->bos) & 0x1) << 8);
    lse |= (p.cake.GetValue("ttl", 64) & 0xFF);

    my->h.lse = htonl(lse);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "lse", "u32", "set the label stack entry" },
    { FT_PKT, "lab", "u20", "set label" },
    { FT_PKT, "tcl", "u3", "set traffic class" },
    { FT_PKT, "bos", "u1", "set bottom of stack" },
    { FT_PKT, "ttl", "u8", "set ttl" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class MplsPimp : public Pimp {
public:
    MplsPimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new MplsProtocol();
    }

    void HelpBind(ostream&) override;
};

void MplsPimp::HelpBind (ostream& out) {
    out << Type() << " -> eth|ip4|ip6|mpls" << endl;
}

Pimp* MplsProtocol::GetPimp () { return new MplsPimp; }

