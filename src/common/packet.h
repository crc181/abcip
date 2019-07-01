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
// packet stuff
//
// used to convey state between users, protcols, and writers.
//-------------------------------------------------------------------------

#ifndef __PACKET_H__
#define __PACKET_H__

#include <cstdint>
#include <string>
#include <iostream>

#ifdef HAVE_DAQ
#include <daq_common.h>
#endif

class Cake;

class Packet {
public:
    Packet(Cake& c) : cake(c) { }

    void Zero();

    void Prepend (const uint8_t* d, uint32_t n);
    void Append (const uint8_t* d, uint32_t n);

    const uint8_t* Data() const;
    uint32_t Length() const;

public:
    Cake& cake;

#ifdef HAVE_DAQ
    DAQ_PktHdr_t daqhdr;
#endif

    bool drop = false;
    uint32_t snap = 0;
    float late = 0.0;

private:
    std::string buf;
};

inline void Packet::Zero () { 
    buf.clear();
}

inline void Packet::Prepend (const uint8_t* d, uint32_t n) {
    if ( !d || !n ) return;
    buf.insert(0, (const char*)d, n);
}

inline void Packet::Append (const uint8_t* d, uint32_t n) {
    if ( !d || !n ) return;
    buf.append((const char*)d, n);
}

inline const uint8_t* Packet::Data() const {
    return (const uint8_t*)buf.data();
}

inline uint32_t Packet::Length() const {
    return buf.length();
}

#endif

