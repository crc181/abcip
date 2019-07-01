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
// ip6 extension hop-by-hop and dest options stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rte6.h"

#include <netinet/in.h>

#include "cake.h"
#include "ip6.h"

using namespace std;

static const char* s_type = "rte6";

struct Rte6Hdr {
    uint8_t next;
    uint8_t len;
    uint8_t type;
    uint8_t segs;
    uint32_t res;
};

class Rte6Impl {
public:
    Rte6Hdr h;
    string addr;
};

Rte6Protocol::Rte6Protocol () : Protocol(s_type) {
    my = new Rte6Impl;
    my->h.next = IPPROTO_NONE;
}

Rte6Protocol::~Rte6Protocol () {
    delete my;
}

bool Rte6Protocol::Bind (const string& type) {
    uint8_t et;

    if ( !Ip6Protocol::GetBinding(type, et) )
        return false;

    my->h.next = et;
    return true;
}

const uint8_t* Rte6Protocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    if ( p.cake.IsSet("next") )
        my->h.next = (uint8_t)p.cake.GetValue("next", 0);

    int n = my->addr.length() / 8;
    if ( n < 0 ) n = 0;
    my->h.len = (uint8_t)p.cake.GetValue("len", n);

    my->h.type = (uint8_t)p.cake.GetValue("type", 0);
    my->h.segs = (uint8_t)p.cake.GetValue("segs", 0);
    my->h.res = (uint32_t)p.cake.GetValue("res", 0);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

const uint8_t* Rte6Protocol::GetOptions (
    const Packet& p, uint32_t& len
) {
    my->addr.clear();

    if ( p.cake.IsSet("addr") ) {
        // add address vector w/o padding
        my->addr += p.cake.GetValue("addr");
    }

    len = my->addr.length();
    return len ? (const uint8_t*)my->addr.data() : nullptr;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "next", "u8", "next proto" },
    { FT_PKT, "len", "u8", "extension header length" },
    { FT_PKT, "type", "u8", "routing type" },
    { FT_PKT, "segs", "u8", "segments left" },
    { FT_PKT, "res", "u32", "reserved" },
    { FT_PKT, "addr", "s*", "address vector" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class Rte6Pimp : public Pimp {
public:
    Rte6Pimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new Rte6Protocol();
    }

    void HelpBind(ostream&) override;
};

void Rte6Pimp::HelpBind (ostream& out) {
    out << Type() << " -> " << Ip6Protocol::GetBindings() << endl;
}

Pimp* Rte6Protocol::GetPimp () { return new Rte6Pimp; }

