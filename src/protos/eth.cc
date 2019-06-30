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
// eth stuff
//-------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX
#include <netinet/ether.h>
#endif

#include "eth.h"
#include "cake.h"

#define ETHERTYPE_IP6   0x86dd
#define ETHERTYPE_VLAN  0x8100
#define ETHERTYPE_RAW   0x0101
#define ETHERTYPE_MPLS  0x8847  // default to unicast
#define ETHERTYPE_PPPOE 0x8864  // session, not discovery

#define ETH_A "2:1:2:3:4:5"
#define ETH_B "2:9:8:7:6:5"

static const char* s_type = "eth";

// from system header:
typedef struct ether_header EthHdr;

class EthImpl {
public:
    EthHdr h;
};

EthProtocol::EthProtocol () : Protocol(s_type) {
    my = new EthImpl;
}

EthProtocol::~EthProtocol () {
    delete my;
}

void EthProtocol::Store (Cake& cake, bool a2b) {
    cake.Store("src", a2b ? ETH_A : ETH_B, true);
    cake.Store("dst", a2b ? ETH_B : ETH_A, true);
    Protocol::Store(cake, a2b);
}

const char* EthProtocol::GetBindings () {
    return "arp|ip4|ip6|mpls|pppoe|raw|vlan";
}

bool EthProtocol::GetBinding (const string& s, uint16_t& et) {
    // FIXTHIS don't hardcode protos

    if ( s == "arp" )
        et = ETHERTYPE_ARP;

    else if ( s == "ip4" )
        et = ETHERTYPE_IP;

    else if ( s == "ip6" )
        et = ETHERTYPE_IP6;

    else if ( s == "mpls" )
        et = ETHERTYPE_MPLS;

    else if ( s == "pppoe" )
        et = ETHERTYPE_PPPOE;

    else if ( s == "raw" )
        et = ETHERTYPE_RAW;

    else if ( s == "vlan" )
        et = ETHERTYPE_VLAN;

    else
        return false;

    return true;
}

bool EthProtocol::Bind (const string& type) {
    uint16_t et;

    if ( !GetBinding(type, et) )
        return false;

    my->h.ether_type = htons(et);
    return true;
}

#define ETH_NULL ((uint8_t*)"\0\0\0\0\0\0")

const uint8_t* EthProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    if ( p.cake.IsSet("type") )
    {
        uint16_t et = 0;
        et = (uint16_t)p.cake.GetValue("type", et);
        my->h.ether_type = htons(et);
    }

    const uint8_t* l2 = (uint8_t*)ether_aton(DstAddr(p));
    if ( !l2 ) l2 = ETH_NULL;
    memcpy(my->h.ether_dhost, l2, sizeof(my->h.ether_dhost));

    l2 = (uint8_t*)ether_aton(SrcAddr(p));
    if ( !l2 ) l2 = ETH_NULL;
    memcpy(my->h.ether_shost, l2, sizeof(my->h.ether_shost));

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "a", "a6", "set host a address" },
    { FT_CFG, "b", "a6", "set host b address" },
    { FT_PKT, "src", "a6", "set source mac address" },
    { FT_PKT, "dst", "a6", "set dest mac address" },
    { FT_PKT, "type", "u16", "set type" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class EthPimp : public Pimp {
public:
    EthPimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new EthProtocol();
    };

    void HelpBind(ostream&);
};

void EthPimp::HelpBind (ostream& out) {
    out << Type() << " -> " << EthProtocol::GetBindings() << endl;
}

Pimp* EthProtocol::GetPimp () { return new EthPimp; }

