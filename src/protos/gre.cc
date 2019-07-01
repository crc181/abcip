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
// gre stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gre.h"

#include <arpa/inet.h>

#include "cake.h"
#include "eth.h"
#include "field.h"
#include "packet.h"
#include "pimp.h"

using namespace std;

static const char* s_type = "gre";

struct GreHdr {
    uint8_t flags;
    uint8_t ver;
    uint16_t proto;
    uint32_t aux[3];
};

class GreImpl {
public:
    GreHdr h;
    unsigned nAux;
    string opt;
};

GreProtocol::GreProtocol () : Protocol(s_type) {
    my = new GreImpl;
}

GreProtocol::~GreProtocol () {
    delete my;
}

bool GreProtocol::Bind (const string& type) {
    uint16_t et;

    if ( !EthProtocol::GetBinding(type, et) )
        return false;

    my->h.proto = htons(et);
    return true;
}

const uint8_t* GreProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->nAux = 0;
    my->h.flags = my->h.ver = 0x00;

    if ( p.cake.IsSet("cks") || p.cake.IsSet("off") || p.cake.IsSet("sre") )
    {
        uint16_t cks = htons(p.cake.GetValue("cks", 0));
        uint16_t off = htons(p.cake.GetValue("off", 0));
        if ( p.cake.IsSet("cks") ) my->h.flags |= 0x80;
        if ( p.cake.IsSet("off") || p.cake.IsSet("sre") )
            my->h.flags |= 0x40;
        my->h.aux[my->nAux++] = (cks << 16) | off;
    }
    // FIXTHIS automatically set len from payLen for ver 1
    if ( p.cake.IsSet("len") || p.cake.IsSet("cid") ) 
    {
        uint16_t cks = htons(p.cake.GetValue("len", 0));
        uint16_t off = htons(p.cake.GetValue("cid", 0));
        my->h.aux[my->nAux++] = (cks << 16) | off;
        my->h.flags |= 0x20;
        my->h.ver |= 0x01;
    }
    if ( p.cake.IsSet("key") )
    {
        my->h.aux[my->nAux++] = htonl(p.cake.GetValue("key", 0));
        my->h.flags |= 0x20;
    }
    if ( p.cake.IsSet("seq") )
    {
        my->h.aux[my->nAux++] = htonl(p.cake.GetValue("seq", 0));
        my->h.flags |= 0x10;
    }
    if ( p.cake.IsSet("ack") )
    {
        my->h.aux[my->nAux++] = htonl(p.cake.GetValue("ack", 0));
        my->h.ver |= 0x80;
    }
    // set flags and ver now to override default flags
    if ( p.cake.IsSet("ctl") )
        my->h.flags = (uint8_t)p.cake.GetValue("ctl", 0x0);

    if ( p.cake.IsSet("ver") )
        my->h.ver = (uint8_t)p.cake.GetValue("ver", 0x0);

    if ( p.cake.IsSet("pro") ) 
        my->h.proto = htons(p.cake.GetValue("pro", my->h.proto));

    len = 4 * (my->nAux + 1);
    return (uint8_t*)&my->h;
}

const uint8_t* GreProtocol::GetOptions (const Packet& p, uint32_t& len) {
    my->opt.clear();

    if ( p.cake.IsSet("sre") ) {
        // add user opts w/o padding
        my->opt += p.cake.GetValue("sre");
    }

    len = my->opt.length();
    return len ? (const uint8_t*)my->opt.data() : nullptr;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "sre", "s*", "set source route entry list" },
    { FT_PKT, "key", "u32", "set key field and K flag" },
    { FT_PKT, "seq", "u32", "set seq number and S flag" },
    { FT_PKT, "ack", "u32", "set ack number and A flag" },
    { FT_PKT, "pro", "u16", "set payload proto" },
    { FT_PKT, "len", "u16", "set payload length (and ver to 1)" },
    { FT_PKT, "cid", "u16", "set call id (and ver to 1)" },
    { FT_PKT, "cks", "u16", "set checksum and C flag" },
    { FT_PKT, "off", "u16", "set offset and R flag" },
    { FT_PKT, "ctl", "u8", "set C R K S s Recur" },
    { FT_PKT, "ver", "u8", "set version, incl A flag" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class GrePimp : public Pimp {
public:
    GrePimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new GreProtocol();
    }

    void HelpBind(ostream&) override;
};

void GrePimp::HelpBind (ostream& out) {
    out << Type() << " -> " << EthProtocol::GetBindings() << endl;
}

Pimp* GreProtocol::GetPimp () { return new GrePimp; }

