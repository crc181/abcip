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
// pseudoheader stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pseudo_hdr.h"

#include <sys/socket.h>

#include "cake.h"
#include "packet.h"
#include "protocol.h"

void PseudoHdr::GetAddresses (
    const Packet& p, const char*& src, const char*& dst
) {
    unsigned lyr = p.cake.GetLayer();
    p.cake.SetLayer(layer);

    src = ip->SrcAddr(p);
    dst = ip->DstAddr(p);

    p.cake.SetLayer(lyr);
}

uint8_t* PseudoHdr4::GetData (const Packet& p, uint16_t n) {
    const char* src, *dst;
    GetAddresses(p, src, dst);

    inet_pton(AF_INET, src, h);
    inet_pton(AF_INET, dst, h+2);

    h[5] = htons(n);
    return (uint8_t*)h;
}

uint8_t* PseudoHdr6::GetData (const Packet& p, uint16_t n) {
    const char* src, *dst;
    GetAddresses(p, src, dst);

    inet_pton(AF_INET6, src, h);
    inet_pton(AF_INET6, dst, h+4);

    h[8] = htonl(n);
    return (uint8_t*)h;
}

