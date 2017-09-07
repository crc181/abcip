//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2013 Charles R. Combs
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
// udp stuff
//-------------------------------------------------------------------------

#include <ostream>

#include "cake.h"
#include "pseudo_hdr.h"
#include "udp.h"

#define UDP_A "48620"
#define UDP_B     "8"

static const char* s_type = "udp";

// typedef struct udphdr UdpHdr;

struct UdpHdr {
    uint16_t src, dst;
    uint16_t len, cks;
};

class UdpImpl {
public:
    UdpHdr h;
    PseudoHdr* ph;
};

UdpProtocol::UdpProtocol (PseudoHdr* ph) : Protocol(s_type) {
    my = new UdpImpl;
    my->ph = ph;
    ph->SetProto(IPPROTO_UDP);
}

UdpProtocol::~UdpProtocol () {
    delete my->ph;
    delete my;
}

void UdpProtocol::Store (Cake& cake, bool a2b) {
    cake.Store("src", a2b ? UDP_A : UDP_B, true);
    cake.Store("dst", a2b ? UDP_B : UDP_A, true);
    Protocol::Store(cake, a2b);
}

const uint8_t* UdpProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.src = htons(SrcPort(p));
    my->h.dst = htons(DstPort(p));

    if ( p.cake.IsSet("ulen") )
        my->h.len = htons(p.cake.GetValue("ulen", p.Length()));
    else
        my->h.len = htons(sizeof(my->h) + p.Length());

    if ( !p.cake.IsSet("cks") )
        Checksum(p);
    else
        my->h.cks = htons((uint16_t)p.cake.GetValue("cks", 0));

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

void UdpProtocol::Checksum (const Packet& p) {
    uint16_t dlen = p.Length();
    const uint8_t* data = p.Data();
    uint16_t ulen = sizeof(my->h) + dlen;

    uint16_t dadj = 0;
    uint8_t dend[2] = { 0, 0 };
    if ( dlen & 0x1 ) dend[dadj++] = data[--dlen];

    CheckField f[] = {
        // pseudoheader
        { (uint16_t*)my->ph->GetData(p, ulen), my->ph->GetLength()>>1 },
        // udp header
        { (uint16_t*)&my->h, sizeof(my->h)>>1 },
        // padded payload
        { (uint16_t*)data, dlen>>1 },
        { (uint16_t*)dend, dadj },
        { NULL, 0 }
    };
    my->h.cks = 0x0000;
    my->h.cks = Protocol::Checksum(f);
    if ( !my->h.cks ) my->h.cks = 0xffff;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "a", "u16", "set host a port" },
    { FT_CFG, "b", "u16", "set host b port" },
    { FT_PKT, "src", "u16", "set source port" },
    { FT_PKT, "dst", "u16", "set dest port" },
    { FT_PKT, "ulen", "u16", "set udp pdu length" },
    { FT_PKT, "cks", "u16", "set checksum" },
    { FT_MAX, NULL, NULL, NULL }
};

class UdpPimp : public Pimp {
public:
    UdpPimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr* ph) {
        return new UdpProtocol(ph);
    };

    void HelpBind(ostream&);
};

void UdpPimp::HelpBind (ostream& out) {
    out << Type() << " -> ip6" << endl;
}

Pimp* UdpProtocol::GetPimp () { return new UdpPimp; }

