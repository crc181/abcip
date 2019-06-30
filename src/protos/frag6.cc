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
// ip6 extension frag stuff
//-------------------------------------------------------------------------

#include <netinet/in.h>

#include "ip6.h"
#include "frag6.h"
#include "cake.h"

using namespace std;

#define IP6_MF  0x1

static const char* s_type = "frag6";

struct Frag6Hdr {
    uint8_t next;
    uint8_t res;
    uint16_t ctl;
    uint32_t id;
};

class Frag6Impl {
public:
    Frag6Hdr h;
    uint32_t id;

    uint16_t last;
    uint16_t offset;

    string buf;
};

Frag6Protocol::Frag6Protocol () : Protocol(s_type) {
    my = new Frag6Impl;
    my->h.next = IPPROTO_NONE;
    my->last = my->offset = 0;
    my->id = 1;
}

Frag6Protocol::~Frag6Protocol () {
    delete my;
}

bool Frag6Protocol::Bind (const string& type) {
    uint8_t et;

    if ( !Ip6Protocol::GetBinding(type, et) )
        return false;

    my->h.next = et;
    return true;
}

const uint8_t* Frag6Protocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.next = (uint8_t)p.cake.GetValue("next", my->h.next);
    my->h.res = (uint8_t)p.cake.GetValue("res", 0);
    my->h.id = htonl((uint32_t)p.cake.GetValue("id", my->id));

    // autofragging is default
    uint16_t ctl = my->offset & ~0x7;
    if ( my->last < my->buf.length() )
        ctl |= IP6_MF;
    else
        my->id++;

    // ctl overrides that
    ctl = (uint16_t)p.cake.GetValue("ctl", ctl);

    // and individual settings override that
    if ( p.cake.IsSet("off") )
        ctl |= ((uint16_t)p.cake.GetValue("off", 0) << 3);

    if ( p.cake.IsSet("r2") )
        ctl |= ((uint16_t)p.cake.GetValue("r2", 0) << 1);

    if ( p.cake.IsSet("m") )
        ctl |= ((uint16_t)p.cake.GetValue("m", 0) & IP6_MF);

    my->h.ctl = htons(ctl);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

const uint8_t* Frag6Protocol::GetPayload (
    const Packet& p, uint32_t& len
) {
    if ( my->last ) {
        my->buf.erase(0, my->last);
        my->offset += my->last;
        my->last = 0;
    }
    uint16_t max = p.cake.GetValue("max", 0);
    max = (max / 8) * 8;

    if ( !my->buf.length() ) {
        my->offset = 0;
        if ( !max ) {
            len = 0;
            return nullptr;
        }
    }
    my->buf.append((char*)p.Data(), p.Length());

    if ( !max || my->buf.length() <= max ) {
        len = my->last = my->buf.length();
        return (uint8_t*)my->buf.data();
    }
    len = my->last = max;
    return (uint8_t*)my->buf.data();
}

bool Frag6Protocol::HasPayload () {
    return ( my->buf.length() > my->last );
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "id", "u32", "fragment id" },
    { FT_PKT, "ctl", "u16", "offset:13 + res:2 + M:1" },
    { FT_PKT, "max", "u16", "fragment at max" },
    { FT_PKT, "next", "u8", "next proto" },
    { FT_PKT, "off", "u13", "fragment offset" },
    { FT_PKT, "res", "u8", "reserved field" },
    { FT_PKT, "r2", "u2", "reserved bits" },
    { FT_PKT, "m", "u1", "more fragments" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class Frag6Pimp : public Pimp {
public:
    Frag6Pimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new Frag6Protocol();
    }

    void HelpBind(ostream&) override;
};

void Frag6Pimp::HelpBind (ostream& out) {
    out << Type() << " -> " << Ip6Protocol::GetBindings() << endl;
}

Pimp* Frag6Protocol::GetPimp () { return new Frag6Pimp; }

