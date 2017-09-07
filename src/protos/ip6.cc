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
// ip6 stuff
//-------------------------------------------------------------------------

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdio.h>

#include "ip6.h"
#include "cake.h"
#include "pseudo_hdr.h"

#define IP6_A  "::ffff:10.1.2" // + .layer
#define IP6_B  "::ffff:10.9.8.7"

// from system header:
// gak! what a nasty little bugger
typedef struct ip6_hdr Ip6Hdr;

static const char* s_type = "ip6";

class Ip6Impl {
public:
    Ip6Hdr h;
};

Ip6Protocol::Ip6Protocol () : Protocol(s_type) {
    my = new Ip6Impl;
    my->h.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_NONE;
}

Ip6Protocol::~Ip6Protocol () {
    delete my;
}

const char* Ip6Protocol::GetBindings () {
    return "dst6|frag6|gre|hop6|icmp6|raw|rte6|tcp|udp|ip4|ip6";
}

bool Ip6Protocol::GetBinding (const string& s, uint8_t& et) {
    if ( s == "dst6" )
        et = IPPROTO_DSTOPTS;

    else if ( s == "frag6" )
        et = IPPROTO_FRAGMENT;

    else if ( s == "gre" )
        et = IPPROTO_GRE;

    else if ( s == "hop6" )
        et = IPPROTO_HOPOPTS;

    else if ( s == "icmp6" )
        et = IPPROTO_ICMPV6;

    else if ( s == "raw" )
        et = IPPROTO_RAW;

    else if ( s == "rte6" )
        et = IPPROTO_ROUTING;

    else if ( s == "tcp" )
        et = IPPROTO_TCP;

    else if ( s == "udp" )
        et = IPPROTO_UDP;

    else if ( s == "ip4" )
        et = IPPROTO_IPIP;

    else if ( s == "ip6" )
        et = IPPROTO_IPV6;

    else 
        return false;

    return true;
}

bool Ip6Protocol::Bind (const string& type) {
    uint8_t pro;

    if ( !GetBinding(type, pro) )
        return false;

    my->h.ip6_ctlun.ip6_un1.ip6_un1_nxt = pro;
    return true;
}

void Ip6Protocol::Store (Cake& cake, bool a2b) {
    char ip6_a[48];
    snprintf(ip6_a, sizeof(ip6_a), "%s.%d", IP6_A, cake.GetLayer());

    cake.Store("src", a2b ? ip6_a : IP6_B, true);
    cake.Store("dst", a2b ? IP6_B : ip6_a, true);

    Protocol::Store(cake, a2b);
}

PseudoHdr* Ip6Protocol::GetPseudoHdr (unsigned lyr) {
    return new PseudoHdr6(this, lyr);
}

const uint8_t* Ip6Protocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    // flow is actually setting ver=6, class=0, flow=1
    my->h.ip6_ctlun.ip6_un1.ip6_un1_flow = 
        htonl((uint32_t)p.cake.GetValue("vcl", 0x60000001));

    my->h.ip6_ctlun.ip6_un1.ip6_un1_hlim = 
        (uint8_t)p.cake.GetValue("hops", IPDEFTTL);

    uint8_t next = my->h.ip6_ctlun.ip6_un1.ip6_un1_nxt;
    my->h.ip6_ctlun.ip6_un1.ip6_un1_nxt = 
        (uint8_t)p.cake.GetValue("next", next);

    uint16_t n = (uint16_t)p.cake.GetValue("tot", p.Length());
    my->h.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(n);

    inet_pton(AF_INET6, SrcAddr(p), &my->h.ip6_src);
    inet_pton(AF_INET6, DstAddr(p), &my->h.ip6_dst);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "a", "a16", "set host a address" },
    { FT_CFG, "b", "a16", "set host b address" },
    { FT_PKT, "src", "a16", "set source address" },
    { FT_PKT, "dst", "a16", "set source address" },
    { FT_PKT, "vcl", "u32", "set version / class / flow" },
    { FT_PKT, "cks", "u16", "set checksum" },
    { FT_PKT, "next", "u8", "set next header" },
    { FT_PKT, "hops", "u8", "set hop limit" },
    { FT_PKT, "tot", "u16", "set payload length" },
    { FT_MAX, NULL, NULL, NULL }
};

class Ip6Pimp : public Pimp {
public:
    Ip6Pimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr*) {
        return new Ip6Protocol();
    };

    void HelpBind(ostream&);
};

void Ip6Pimp::HelpBind (ostream& out) {
    out << Type() << " -> " << Ip6Protocol::GetBindings() << endl;
}

Pimp* Ip6Protocol::GetPimp () { return new Ip6Pimp; }

