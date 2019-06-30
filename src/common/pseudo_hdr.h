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

#ifndef __PSEUDO_HDR_H__
#define __PSEUDO_HDR_H__

#include <stdint.h>
#include <arpa/inet.h>
#include "protocol.h"

class PseudoHdr {
public:
    virtual ~PseudoHdr() { };
    virtual uint8_t* GetData(const Packet&, uint16_t) = 0;
    virtual uint16_t GetLength() = 0;
    virtual void SetProto(int proto) = 0;

protected:
    PseudoHdr(Protocol* p, unsigned lyr) { ip = p; layer = lyr; };
    void GetAddresses(const Packet&, const char*& src, const char*& dst);

private:
    unsigned layer;
    Protocol* ip;
};

class PseudoHdr4 : public PseudoHdr {
public:
    PseudoHdr4(Protocol* p, unsigned lyr) : PseudoHdr(p, lyr) { };
    ~PseudoHdr4() override { };
    
    uint8_t* GetData(const Packet&, uint16_t) override;
    void SetProto(int proto) override { h[4] = htons(proto); };
    uint16_t GetLength() override { return sizeof(h); };

private:
    uint16_t h[6];
};

class PseudoHdr6 : public PseudoHdr {
public:
    PseudoHdr6(Protocol* p, unsigned lyr) : PseudoHdr(p, lyr) { };
    ~PseudoHdr6() override { };
    
    uint8_t* GetData(const Packet&, uint16_t) override;
    void SetProto(int proto) override { h[9] = htonl(proto); };
    uint16_t GetLength() override { return sizeof(h); };

private:
    uint32_t h[10];
};

#endif

