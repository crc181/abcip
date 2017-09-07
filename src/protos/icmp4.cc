//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2013 Charles R. Combs
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
// icmp4 stuff
//-------------------------------------------------------------------------

#include <iostream>

#define ICMP_ECHO 8

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "icmp4.h"
#include "cake.h"

static const char* s_type = "icmp4";

struct Icmp4Hdr {
    uint8_t type;
    uint8_t code;

    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
};

class Icmp4Impl {
public:
    Icmp4Hdr h;
};

Icmp4Protocol::Icmp4Protocol () : Protocol(s_type) {
    my = new Icmp4Impl;
}

Icmp4Protocol::~Icmp4Protocol () {
    delete my;
}

const uint8_t* Icmp4Protocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.type = (uint8_t)p.cake.GetValue("type", ICMP_ECHO);
    my->h.code = (uint8_t)p.cake.GetValue("code", 0x0);

    if ( p.cake.IsSet("u32") ) {
        uint32_t u32 = (p.cake.GetValue("u32", 0));
        my->h.id = htons(u32 >> 16);
        my->h.seq = htons(u32 & 0xffff);
    } else {
        my->h.id = htons((uint16_t)p.cake.GetValue("id", 1));
        my->h.seq = htons((uint16_t)p.cake.GetValue("seq", 1));
    }
    if ( !p.cake.IsSet("cks") ) Checksum(p);
    else my->h.cksum = htons((uint16_t)p.cake.GetValue("cks", 0));

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

void Icmp4Protocol::Checksum (const Packet& p) {
    uint16_t dlen = p.Length();
    const uint8_t* data = p.Data();

    uint16_t dadj = 0;
    uint8_t dend[2] = { 0, 0 };  // alignment
    if ( dlen & 0x1 ) dend[dadj++] = data[--dlen];

    CheckField f[] = {
        // icmp4 header
        { (uint16_t*)&my->h, sizeof(my->h) >> 1 },
        // padded payload
        { (uint16_t*)data, (uint16_t)(dlen>>1) },  // alignment
        { (uint16_t*)dend, dadj },
        { NULL, 0 }
    };
    my->h.cksum = 0x0000;
    my->h.cksum = Protocol::Checksum(f);
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "data", "s*", "set in lieu of next layer(s)" },
    { FT_PKT, "type", "u8", "set type field" },
    { FT_PKT, "code", "u8", "set code field" },
    { FT_PKT, "cks", "u16", "set checksum" },
    { FT_PKT, "id", "u16", "set id" },
    { FT_PKT, "seq", "u16", "set sequence number" },
    { FT_PKT, "u32", "u32", "set in lieu of id/seq" },
    { FT_MAX, NULL, NULL, NULL }
};

class Icmp4Pimp : public Pimp {
public:
    Icmp4Pimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new Icmp4Protocol();
    };
};

Pimp* Icmp4Protocol::GetPimp () { return new Icmp4Pimp; }

