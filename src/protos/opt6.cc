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

#include <netinet/in.h>

#include "ip6.h"
#include "opt6.h"
#include "cake.h"

struct Opt6Hdr {
    uint8_t next;
    uint8_t len;
};

class Opt6Impl {
public:
    Opt6Hdr h;
    string opt;
};

Opt6Protocol::Opt6Protocol (const char* s) : Protocol(s) {
    my = new Opt6Impl;
    my->h.next = IPPROTO_NONE;
}

Opt6Protocol::~Opt6Protocol () {
    delete my;
}

bool Opt6Protocol::Bind (const string& type) {
    uint8_t et;

    if ( !Ip6Protocol::GetBinding(type, et) )
        return false;

    my->h.next = et;
    return true;
}

const uint8_t* Opt6Protocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    if ( p.cake.IsSet("next") )
        my->h.next = (uint8_t)p.cake.GetValue("next", 0);

    int n = my->opt.length() / 8 - 1;
    if ( n < 0 ) n = 0;
    my->h.len = (uint8_t)p.cake.GetValue("len", n);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

const uint8_t* Opt6Protocol::GetOptions (
    const Packet& p, uint32_t& len
) {
    my->opt.clear();

    if ( p.cake.IsSet("opt") ) {
        // add user opts w/o padding
        my->opt += p.cake.GetValue("opt");
    } else {
        my->opt.append(6, '\0');
    }

    len = my->opt.length();
    return len ? (uint8_t*)my->opt.data() : nullptr;
}

//-------------------------------------------------------------------------

static void HelpBind (const char* type, ostream& out) {
    out << type << " -> " << Ip6Protocol::GetBindings() << endl;
}

static Field s_fields[] = {
    { FT_PKT, "next", "u8", "next proto" },
    { FT_PKT, "len", "u8", "options header length" },
    { FT_PKT, "opt", "s*", "options octets" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------

static const char* s_hop = "hop6";

class Hop6Pimp : public Pimp {
public:
    Hop6Pimp() : Pimp(s_hop, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new Hop6Protocol();
    };

    void HelpBind(ostream&);
};

void Hop6Pimp::HelpBind (ostream& out) {
    ::HelpBind(s_hop, out);
}

Pimp* Hop6Protocol::GetPimp () { return new Hop6Pimp; }

//-------------------------------------------------------------------------

static const char* s_dst = "dst6";

class Dst6Pimp : public Pimp {
public:
    Dst6Pimp() : Pimp(s_dst, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new Dst6Protocol();
    };

    void HelpBind(ostream&);
};

void Dst6Pimp::HelpBind (ostream& out) {
    ::HelpBind(s_dst, out);
}

Pimp* Dst6Protocol::GetPimp () { return new Dst6Pimp; }

