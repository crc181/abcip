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
// geneve stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "geneve.h"

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__darwin__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <netinet/if_ether.h>
#endif

#include <arpa/inet.h>

#include "cake.h"
#include "eth.h"
#include "field.h"
#include "packet.h"
#include "pimp.h"

#define RFC_8926_GENEVE_VERSION     0
#define GENEVE_ETH_TYPE             0x6558
#define GENEVE_FLAG_O               0x80
#define GENEVE_FLAG_C               0x40

using namespace std;

static const char* s_type = "geneve";

struct GeneveHdr
{
    uint8_t g_vol;
    uint8_t g_flags;
    uint16_t g_proto;
    uint8_t g_vni[3];
    uint8_t g_rsvd2;

    void set_version(uint8_t version)
    {
        g_vol &= ~0xC0;
        g_vol |= ((version << 6) & 0xC0);
    }

    void set_optlen(uint8_t optlen)
    {
        g_vol &= ~0x3f;
        g_vol |= ((optlen / 4) & 0x3f);
    }

    int get_flag(uint8_t flag)
    { return ((g_flags & flag) == flag); }

    void set_flag(uint8_t flag)
    { g_flags |= flag; }

    void clr_flag(uint8_t flag)
    { g_flags &= ~flag; }

    void set_proto(uint16_t proto)
    { g_proto = proto; }

    void set_vni(uint32_t vni)
    {
        g_vni[0] = (vni >> 16) & 0xff;
        g_vni[1] = (vni >>  8) & 0xff;
        g_vni[2] = (vni >>  0) & 0xff;
    }
};

class GeneveImpl {
public:
    GeneveHdr h;
    string opt;
    uint32_t vni = 0;
};

GeneveProtocol::GeneveProtocol() : Protocol(s_type) {
    my = new GeneveImpl();
}

GeneveProtocol::~GeneveProtocol() {
    delete my;
}

bool GeneveProtocol::Bind (const string& type)
{
    uint16_t proto = 0;

    if ( type == "eth" )
        proto = htons(GENEVE_ETH_TYPE);

    else if ( type == "ip4" )
        proto = htons(ETHERTYPE_IP);

    else if ( type == "ip6" )
        proto = htons(ETHERTYPE_IPV6);

    else if ( type == "arp" )
        proto = htons(ETHERTYPE_ARP);

    if ( proto == 0 )
        return false;

    my->h.set_proto(proto);
    return true;
}

void GeneveProtocol::Fetch(Cake& cake, bool)
{
    my->vni = cake.GetValue("vni", my->vni);

    if ( cake.IsSet("opt") )
        my->opt += cake.GetValue("opt");

    if ( cake.IsSet("c") )
        my->h.set_flag(GENEVE_FLAG_C);

    if ( cake.IsSet("o") )
        my->h.set_flag(GENEVE_FLAG_O);
}

const uint8_t* GeneveProtocol::GetHeader(Packet& p, uint32_t& len)
{
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.set_version(p.cake.GetValue("ver", 0));

    if ( p.cake.IsSet("o") ) {
        uint8_t val = p.cake.GetValue("o", my->h.get_flag(GENEVE_FLAG_O));
        if ( val )
            my->h.set_flag(GENEVE_FLAG_O);
        else
            my->h.clr_flag(GENEVE_FLAG_O);
    }

    if ( p.cake.IsSet("c") ) {
        uint8_t val = p.cake.GetValue("c", my->h.get_flag(GENEVE_FLAG_C));
        if ( val )
            my->h.set_flag(GENEVE_FLAG_C);
        else
            my->h.clr_flag(GENEVE_FLAG_C);
    }

    my->h.set_optlen(p.cake.GetValue("olen", (uint32_t)my->opt.length()));
    my->h.set_vni(my->vni);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

const uint8_t* GeneveProtocol::GetOptions(const Packet& p, uint32_t& len)
{
    if ( p.cake.IsSet("opt") )
    {
        my->opt.clear();
        my->opt += p.cake.GetValue("opt");
    }
    len = my->opt.length();
    return len ? (const uint8_t*)my->opt.data() : nullptr;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "vni",  "u32", "set virtual network identifier" },
    { FT_CFG, "opt",  "s*",  "set option octets" },
    { FT_CFG, "c",    "u8",  "set/clear C flag" },
    { FT_CFG, "o",    "u8",  "set/clear O flag" },

    { FT_PKT, "opt",  "s*",  "set option octets" },
    { FT_PKT, "c",    "u8",  "set/clear C flag" },
    { FT_PKT, "o",    "u8",  "set/clear O flag" },
    { FT_PKT, "ver",  "u8",  "set version" },
    { FT_PKT, "olen", "u8",  "set option length" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class GenevePimp : public Pimp {
public:
    GenevePimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new GeneveProtocol();
    }

    void HelpBind(ostream&) override;
};

void GenevePimp::HelpBind (ostream& out)
{
    out << Type() << " -> arp|eth|ip4|ip6" << endl;
}

Pimp* GeneveProtocol::GetPimp()
{
    return new GenevePimp;
}
