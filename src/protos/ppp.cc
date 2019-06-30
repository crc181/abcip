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

/*
 * provides encapsulation for ip4 and ip6
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ppp.h"

#include <ostream>

#include "cake.h"

using namespace std;

#define PPP_IP4 0x0021
#define PPP_IP6 0x0057

static const char* s_type = "ppp";

struct PppHdr
{
    uint16_t hdr;
};

class PppImpl
{
    public:
    PppHdr h;
};

PppProtocol::PppProtocol ():Protocol (s_type)
{
    my = new PppImpl;
}

PppProtocol::~PppProtocol ()
{
    delete my;
}

bool PppProtocol::Bind (const string& type) {
    if ( type == "ip4" )
        my->h.hdr = htons((uint16_t)PPP_IP4);

    else if ( type == "ip6" )
        my->h.hdr = htons((uint16_t)PPP_IP6);

    else
        return false;

    return true;
}

const uint8_t* PppProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    len = sizeof(my->h);
    return (uint8_t *)&my->h;
}

//-------------------------------------------------------------------------

class PppPimp : public Pimp {
public:
    PppPimp() : Pimp(s_type, nullptr) { }

    Protocol* New(PseudoHdr*) override {
        return new PppProtocol();
    }

    void HelpBind(ostream&) override;
};

void PppPimp::HelpBind (ostream& out) {
    out << Type () << " -> ip4|ip6" << endl;
}

Pimp* PppProtocol::GetPimp () { return new PppPimp; }

