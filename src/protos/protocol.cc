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
// protocol stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "protocol.h"

#include <cstdlib>

#include "pseudo_hdr.h"

using namespace std;

//-------------------------------------------------------------------------
// FIXTHIS create strings/defines for "a", "src", etc.

void Protocol::Store (Cake&, bool) { }
void Protocol::Fetch (Cake&, bool) { }

const char* Protocol::SrcAddr (const Packet& p) {
    return p.cake.GetCValue("src");
}

const char* Protocol::DstAddr (const Packet& p) {
    return p.cake.GetCValue("dst");
}

uint16_t Protocol::SrcPort (const Packet& p) {
    return atoi(SrcAddr(p));
}

uint16_t Protocol::DstPort (const Packet& p) {
    return atoi(DstAddr(p));
}

uint16_t Protocol::Checksum (const CheckField* f) {
    uint32_t sum = 0;

    while ( f->data ) {
        for ( int i = 0; i < f->len; i++ )
            sum += f->data[i];
        f++;
    }
    sum  = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);
 
    return (uint16_t)(~sum);
}

const uint8_t* Protocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const string& s = p.cake.GetValue("head");
    len = s.length();
    return len ? (const uint8_t*)s.data() : nullptr;
}

const uint8_t* Protocol::GetTrailer (
    const Packet& p, uint32_t& len
) {
    const string& s = p.cake.GetValue("tail");
    len = s.length();
    return len ? (const uint8_t*)s.data() : nullptr;
}

