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
// vlan stuff
//-------------------------------------------------------------------------


#include "cake.h"
#include "eth.h"
#include "vlan.h"

#include <net/ethernet.h>

static const char* s_type = "vlan";

// placing pid last allows normal chaining / encapsulation
// instead of making this an optional part of the eth header
//
struct VlanHdr {
    uint16_t vid;
    uint16_t pid;
};

class VlanImpl {
public:
    VlanHdr h;
};

VlanProtocol::VlanProtocol () : Protocol(s_type) {
    my = new VlanImpl;
}

VlanProtocol::~VlanProtocol () {
    delete my;
}

bool VlanProtocol::Bind (const string& type) {
    uint16_t et;

    if ( !EthProtocol::GetBinding(type, et) )
        return false;

    my->h.pid = htons(et);
    return true;
}

void VlanProtocol::Store (Cake& cake, bool a2b) {
    cake.Store("vid", "1", true);
    Protocol::Store(cake, a2b);
}

const uint8_t* VlanProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    if ( p.cake.IsSet("pid") )
        my->h.pid = htons((uint16_t)p.cake.GetValue("pid", 0));

    uint16_t vid = (uint16_t)p.cake.GetValue("vid", 0);

    vid |= (((uint8_t)p.cake.GetValue("pcp", 0)) & 0x7) << 13;
    vid |= (((uint8_t)p.cake.GetValue("cfi", 0)) & 0x1) << 12;

    my->h.vid = htons(vid);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "pcp", "u3", "set priority" },
    { FT_PKT, "cfi", "u1", "set canonical indicator" },
    { FT_PKT, "vid", "u12", "set vlan id" },
    { FT_MAX, "pid", "u16", "set protocol id" },
};

class VlanPimp : public Pimp {
public:
    VlanPimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new VlanProtocol();
    };

    void HelpBind(ostream&);
};

void VlanPimp::HelpBind (ostream& out) {
    out << Type() << " -> " << EthProtocol::GetBindings() << endl;
}

Pimp* VlanProtocol::GetPimp () { return new VlanPimp; }

