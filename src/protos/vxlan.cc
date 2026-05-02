//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2026 Charles R. Combs
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
// vxlan stuff (RFC 7348)
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "vxlan.h"

#include "cake.h"
#include "field.h"
#include "packet.h"
#include "pimp.h"

#define VXLAN_FLAG_I    0x08

using namespace std;

static const char* s_type = "vxlan";

struct VxlanHdr
{
    uint8_t  flags;
    uint8_t  rsvd1[3];
    uint8_t  vni[3];
    uint8_t  rsvd2;

    void set_vni(uint32_t v)
    {
        vni[0] = (v >> 16) & 0xff;
        vni[1] = (v >>  8) & 0xff;
        vni[2] = (v >>  0) & 0xff;
    }
};

class VxlanImpl {
public:
    VxlanHdr h = {};
    uint32_t vni = 0;
};

VxlanProtocol::VxlanProtocol() : Protocol(s_type) {
    my = new VxlanImpl();
    my->h.flags = VXLAN_FLAG_I;
}

VxlanProtocol::~VxlanProtocol() {
    delete my;
}

void VxlanProtocol::Fetch(Cake& cake, bool)
{
    my->vni = cake.GetValue("vni", my->vni);

    if ( cake.IsSet("flags") )
        my->h.flags = cake.GetValue("flags", (uint32_t)my->h.flags);

    if ( cake.IsSet("rsvd1") )
    {
        uint32_t v = cake.GetValue("rsvd1", (uint32_t)0);
        my->h.rsvd1[0] = (v >> 16) & 0xff;
        my->h.rsvd1[1] = (v >>  8) & 0xff;
        my->h.rsvd1[2] = (v >>  0) & 0xff;
    }

    if ( cake.IsSet("rsvd2") )
        my->h.rsvd2 = cake.GetValue("rsvd2", (uint32_t)my->h.rsvd2);
}

const uint8_t* VxlanProtocol::GetHeader(Packet& p, uint32_t& len)
{
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    if ( p.cake.IsSet("flags") )
        my->h.flags = p.cake.GetValue("flags", (uint32_t)my->h.flags);

    if ( p.cake.IsSet("rsvd1") )
    {
        uint32_t v = p.cake.GetValue("rsvd1", (uint32_t)0);
        my->h.rsvd1[0] = (v >> 16) & 0xff;
        my->h.rsvd1[1] = (v >>  8) & 0xff;
        my->h.rsvd1[2] = (v >>  0) & 0xff;
    }

    my->h.set_vni(p.cake.GetValue("vni", my->vni));

    if ( p.cake.IsSet("rsvd2") )
        my->h.rsvd2 = p.cake.GetValue("rsvd2", (uint32_t)my->h.rsvd2);

    len = sizeof(my->h);
    return (const uint8_t*)&my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "vni",   "u32", "set virtual network identifier" },
    { FT_CFG, "flags", "u8",  "set flags byte (default: 0x08 = VNI present)" },
    { FT_CFG, "rsvd1", "u24", "set reserved bytes 1-3" },
    { FT_CFG, "rsvd2", "u8",  "set reserved byte 8" },
    { FT_PKT, "flags", "u8",  "set flags byte" },
    { FT_PKT, "rsvd1", "u24", "set reserved bytes 1-3" },
    { FT_PKT, "vni",   "u32", "set virtual network identifier" },
    { FT_PKT, "rsvd2", "u8",  "set reserved byte 8" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class VxlanPimp : public Pimp {
public:
    VxlanPimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new VxlanProtocol();
    }

    void HelpBind(ostream&) override;
};

void VxlanPimp::HelpBind(ostream& out)
{
    out << Type() << " -> eth" << endl;
}

Pimp* VxlanProtocol::GetPimp()
{
    return new VxlanPimp;
}
