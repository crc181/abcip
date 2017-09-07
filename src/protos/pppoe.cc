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
// PPP over Ethenet stuff
//-------------------------------------------------------------------------

#include <stdio.h>
#include <ostream>

#include "cake.h"
#include "pppoe.h"

static const char* s_type = "pppoe";

struct PPPoEHdr {
    uint8_t ver:4;
    uint8_t type:4;
    uint8_t code;
    uint16_t sid;
    uint16_t len;
};

class PPPoEImpl {
public:
    PPPoEHdr h;
};

PPPoEProtocol::PPPoEProtocol() : Protocol(s_type)
{
    my = new PPPoEImpl;
}

PPPoEProtocol::~PPPoEProtocol ()
{
    delete my;
}

bool PPPoEProtocol::Bind (const string& type) {
    if ( type == "ppp" )
        return true;

    return false;
}

const uint8_t* PPPoEProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.ver = htons((uint16_t)p.cake.GetValue("ver", 1));
    my->h.type = htons((uint16_t)p.cake.GetValue("type", 1));
    my->h.code = htons((uint16_t)p.cake.GetValue("code", 0));
    my->h.sid = htons((uint16_t)p.cake.GetValue("sid", 2));
    my->h.len = htons((uint16_t)p.cake.GetValue("plen", p.Length()));

    len = sizeof(my->h);
    return (uint8_t*) & my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "ver", "u4", "version" },
    { FT_PKT, "type", "u4", "type" },
    { FT_PKT, "code", "u4", "code" },
    { FT_PKT, "sid", "u16", "session id" },
    { FT_PKT, "plen", "u16", "length" },
    { FT_MAX, NULL, NULL, NULL }
};

class PPPoEPimp : public Pimp {
public:
    PPPoEPimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new PPPoEProtocol();
    };

    void HelpBind(ostream&);
};

void PPPoEPimp::HelpBind (ostream& out) {
    out << Type() << " -> ppp" << endl;
}

Pimp* PPPoEProtocol::GetPimp () {
    return new PPPoEPimp;
}

