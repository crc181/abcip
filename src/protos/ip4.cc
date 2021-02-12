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
// ip4 stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ip4.h"

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__darwin__) || defined(__OpenBSD__)
#include <sys/types.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>

#include "cake.h"
#include "field.h"
#include "packet.h"
#include "pimp.h"
#include "pseudo_hdr.h"

using namespace std;

#define IP4_A   "10.1.2"  // + .layer
#define IP4_B   "10.9.8.7"

#define IP4_RF  0x8000
#define IP4_DF  0x4000
#define IP4_MF  0x2000

#define IP4_VER 0x4

// FIXTHIS delete from Protocol ctor?
static const char* s_type = "ip4";

// from system header:
typedef struct ip Ip4Hdr;

class Ip4Impl {
public:
    Ip4Hdr h;
    int id;

    uint16_t last;
    uint16_t offset;

    string opt;
    string buf;
};

Ip4Protocol::Ip4Protocol () : Protocol(s_type) {
    my = new Ip4Impl;
    my->h.ip_p = IPPROTO_NONE;
    my->id = 1;
    my->last = my->offset = 0;
}

Ip4Protocol::~Ip4Protocol () {
    delete my;
}

bool Ip4Protocol::Bind (const string& type) {
    if ( type == "tcp" )
        my->h.ip_p = IPPROTO_TCP;

    else if ( type == "udp" )
        my->h.ip_p = IPPROTO_UDP;

    else if ( type == "icmp4" )
        my->h.ip_p = IPPROTO_ICMP;

    else if ( type == "gre" )
        my->h.ip_p = IPPROTO_GRE;

    else if ( type == "raw" )
        my->h.ip_p = IPPROTO_RAW;

    else if ( type == "ip4" )
        my->h.ip_p = IPPROTO_IPIP;

    else if ( type == "ip6" )
        my->h.ip_p = IPPROTO_IPV6;

    else if ( type == "mpls" )
        my->h.ip_p = IPPROTO_MPLS;

    else
        return false;

    return true;
}


void Ip4Protocol::Store (Cake& cake, bool a2b) {
#if 0
    // uh, wtf?
    stringstream ss;
    ss << IP4_A << cake.GetLayer();
    const char* ip4_a = ss.str().c_str();
#else
    char ip4_a[16];
    snprintf(ip4_a, sizeof(ip4_a), "%s.%u", IP4_A, cake.GetLayer());
#endif

    cake.Store("src", a2b ? ip4_a : IP4_B, true);
    cake.Store("dst", a2b ? IP4_B : ip4_a, true);

    Protocol::Store(cake, a2b);
}

PseudoHdr* Ip4Protocol::GetPseudoHdr (unsigned lyr) {
    return new PseudoHdr4(this, lyr);
}

const uint8_t* Ip4Protocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.ip_id = htons((uint16_t)p.cake.GetValue("id", my->id));

    my->h.ip_v = (uint8_t)p.cake.GetValue("ver", IP4_VER);
    my->h.ip_tos = (uint8_t)p.cake.GetValue("tos", 0x0);
    my->h.ip_ttl = (uint8_t)p.cake.GetValue("ttl", IPDEFTTL);

    // autofragging is default
    uint16_t frag = my->offset >> 3;
    if ( my->last < my->buf.length() )
        frag |= IP4_MF;
    else
        my->id++;

    // frag overrides that
    frag = (uint16_t)p.cake.GetValue("frag", frag);
    // and offset and flags override that
    frag = (uint16_t)p.cake.GetValue("off", frag);

    if ( p.cake.IsSet("rf") ) frag |= IP4_RF;
    if ( p.cake.IsSet("df") ) frag |= IP4_DF;
    if ( p.cake.IsSet("mf") ) frag |= IP4_MF;

    my->h.ip_off = htons(frag);

    int n = sizeof(my->h) + my->opt.length();
    my->h.ip_hl = (uint8_t)p.cake.GetValue("ihl", (n >> 2));

    n = sizeof(my->h) + p.Length();  // pay includes opts
    my->h.ip_len = htons((uint16_t)p.cake.GetValue("tot", n));

    inet_aton(SrcAddr(p), (struct in_addr*)&my->h.ip_src);
    inet_aton(DstAddr(p), (struct in_addr*)&my->h.ip_dst);

    if ( p.cake.IsSet("pro") )
        my->h.ip_p = (uint8_t)p.cake.GetValue("pro", my->h.ip_p);

    if ( !p.cake.IsSet("cks") ) Checksum(p);
    else my->h.ip_sum = htons((uint16_t)p.cake.GetValue("cks", 0));

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

const uint8_t* Ip4Protocol::GetOptions (
    const Packet& p, uint32_t& len
) {
    my->opt.clear();

    if ( p.cake.IsSet("opt") ) {
        // add user opts w/o padding
        my->opt += p.cake.GetValue("opt");
    }

    len = my->opt.length();
    return len ? (const uint8_t*)my->opt.data() : nullptr;
}

const uint8_t* Ip4Protocol::GetPayload (
    const Packet& p, uint32_t& len
) {
    if ( my->last ) {
        my->buf.erase(0, my->last);
        my->offset += my->last;
        my->last = 0;
    }
    uint16_t max = p.cake.GetValue("max", 0);
    max = (max / 8) * 8;

    if ( !my->buf.length() ) {
        my->offset = 0;
        if ( !max ) {
            len = 0;
            return nullptr;
        }
    }
    my->buf.append((const char*)p.Data(), p.Length());

    if ( !max || my->buf.length() <= max ) {
        len = my->last = my->buf.length();
        return (const uint8_t*)my->buf.data();
    }
    len = my->last = max;
    return (const uint8_t*)my->buf.data();
}

bool Ip4Protocol::HasPayload () {
    return ( my->buf.length() > my->last );
}

// FIXTHIS really should ensure 2-byte alignment where
// indicated below.  Same for Tcp/UdpProtocol::Checksum().
void Ip4Protocol::Checksum (const Packet&) {
    uint16_t olen = my->opt.length();
    const uint8_t* opts = (const uint8_t*)my->opt.data();

    uint16_t oadj = 0;
    uint8_t oend[2] = { 0, 0 };
    if ( olen & 0x1 ) oend[oadj++] = opts[--olen];

    CheckField f[] = {
        { (uint16_t*)&my->h, (int)sizeof(my->h) / 2 },
        // padded options
        { (const uint16_t*)opts, (uint16_t)(olen>>1) },  // alignment
        { (uint16_t*)oend, oadj },
        { nullptr, 0 }
    };
    my->h.ip_sum = 0x0000;
    my->h.ip_sum = Protocol::Checksum(f);
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "a", "a4", "set host a address" },
    { FT_CFG, "b", "a4", "set host b address" },
    { FT_PKT, "src", "a4", "set source address" },
    { FT_PKT, "dst", "a4", "set dest address" },
    { FT_PKT, "opt", "s*", "set options octets" },
    { FT_PKT, "frag", "u16", "set frag flags/offset" },
    { FT_PKT, "off", "u13", "set frag offset" },
    { FT_PKT, "rf", "u1", "set reserved flag" },
    { FT_PKT, "df", "u1", "set don't frag flag" },
    { FT_PKT, "mf", "u1", "set more frags flag" },
    { FT_PKT, "id", "u16", "set ip/frag id" },
    { FT_PKT, "tot", "u16", "set datagram length" },
    { FT_PKT, "max", "u16", "fragment at max" },
    { FT_PKT, "cks", "u16", "set checksum" },
    { FT_PKT, "pro", "u8", "set protocol number" },
    { FT_PKT, "tos", "u8", "set tos/diff-serv" },
    { FT_PKT, "ttl", "u8", "set ttl" },
    { FT_PKT, "ihl", "u4", "set header length" },
    { FT_PKT, "ver", "u4", "set version" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class Ip4Pimp : public Pimp {
public:
    Ip4Pimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new Ip4Protocol();
    }

    void HelpBind(ostream&) override;
};

void Ip4Pimp::HelpBind (ostream& out) {
    out << Type() << " -> gre|icmp4|tcp|udp|raw|ip4|ip6" << endl;
}

Pimp* Ip4Protocol::GetPimp () { return new Ip4Pimp; }

