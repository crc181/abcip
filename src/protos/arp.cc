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
// arp stuff
//-------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX
#include <netinet/ether.h>
#endif

#ifdef MACOSX
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#endif

#include <iostream>

#include "cake.h"
#include "arp.h"

struct ArpHdr {
    uint16_t hw;
    uint16_t ip;

    uint8_t hw_len;
    uint8_t ip_len;

    uint16_t op;
};

// eth/ip is the default
struct EthIpMap {
    uint8_t shw[6];
    uint8_t sip[4];
    uint8_t thw[6];
    uint8_t tip[4];
};

class ArpImpl {
public:
    ArpHdr h;
    EthIpMap map;
};

static const char* s_type = "arp";

static const char* ETH_A = "2:1:2:3:4:5";
static const char* ETH_B = "2:9:8:7:6:5";

static const char* IP4_A = "10.1.2.1";
static const char* IP4_B = "10.9.8.1";

ArpProtocol::ArpProtocol () : Protocol(s_type) {
    my = new ArpImpl;
}

ArpProtocol::~ArpProtocol () {
    delete my;
}

void ArpProtocol::Store (Cake& cake, bool a2b) {
    cake.Store("shw", a2b ? ETH_A : ETH_B, true);
    cake.Store("thw", a2b ? ETH_B : ETH_A, true);
    cake.Store("src", a2b ? IP4_A : IP4_B, true);
    cake.Store("dst", a2b ? IP4_B : IP4_A, true);
    Protocol::Store(cake, a2b);
}

const uint8_t* ArpProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.hw = (uint16_t)htons(p.cake.GetValue("hwt", 1));  // eth
    my->h.ip = (uint16_t)htons(p.cake.GetValue("ipt", 0x0800));  // ip4
    my->h.op = (uint16_t)htons(p.cake.GetValue("op", 1));  // req

    my->h.hw_len = (uint8_t)p.cake.GetValue("hwn", 6);
    my->h.ip_len = (uint8_t)p.cake.GetValue("ipn", 4);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

#define ETH_NULL ((uint8_t*)"\0\0\0\0\0\0")

const uint8_t* ArpProtocol::GetOptions (
    const Packet& p, uint32_t& len
) {
    const string& s = p.cake.GetValue("addr");
    len = s.length();

    if ( len )
        return (uint8_t*)s.data();

    const char* hw = p.cake.GetCValue("shw");
    const uint8_t* l2 = (uint8_t*)ether_aton(hw);
    if ( !l2 ) l2 = ETH_NULL;
    memcpy(my->map.shw, l2, sizeof(my->map.shw));

    hw = p.cake.GetCValue("thw");
    l2 = (uint8_t*)ether_aton(hw);
    if ( !l2 ) l2 = ETH_NULL;
    memcpy(my->map.thw, l2, sizeof(my->map.thw));

    inet_aton(p.cake.GetCValue("sip"), (struct in_addr*)&my->map.sip);
    inet_aton(p.cake.GetCValue("tip"), (struct in_addr*)&my->map.tip);

    len = sizeof(my->map);
    return (uint8_t*)&my->map;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "addr", "s*", "all address fields" },
    { FT_PKT, "data", "s*", "any data after addresses" },
    { FT_PKT, "shw", "a6", "src eth address" },
    { FT_PKT, "thw", "a6", "dst eth address" },
    { FT_PKT, "sip", "a4", "src ip4 address" },
    { FT_PKT, "tip", "a4", "dst ip4 address" },
    { FT_PKT, "hwt", "u16", "set hardware type" },
    { FT_PKT, "ipt", "u16", "set proto type" },
    { FT_PKT, "op", "u16", "set opcode" },
    { FT_PKT, "hwn", "u8", "set hardware length" },
    { FT_PKT, "ipn", "u8", "set proto length" },
    { FT_MAX, NULL, NULL, NULL }
};

class ArpPimp : public Pimp {
public:
    ArpPimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new ArpProtocol();
    };
};

Pimp* ArpProtocol::GetPimp () { return new ArpPimp; }

