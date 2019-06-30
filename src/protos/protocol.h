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

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <stdint.h>
#include <arpa/inet.h>

#include "cake.h"
#include "packet.h"
#include "pimp.h"

class PseudoHdr;

struct CheckField {
    uint16_t* data;
    uint16_t len; // number of shorts at data
};

class Protocol {
public:
    virtual ~Protocol() = default;

    virtual void Store(Cake&, bool a2b);
    virtual void Fetch(Cake&, bool a2b);

    const string& GetType() { return type; };
    virtual bool Bind(const string&) { return true; };

    virtual PseudoHdr* GetPseudoHdr(unsigned /*lyr*/) { return nullptr; };

    // Packet should really be const but phy needs access
    // for now, only phy should be directly changing Packet!
    virtual const uint8_t* GetHeader(Packet&, uint32_t& len);
    virtual const uint8_t* GetTrailer(const Packet&, uint32_t& len);

    virtual const uint8_t* GetOptions(const Packet&, uint32_t& len) {
        len = 0; return nullptr;
    };
    virtual const uint8_t* GetPayload(const Packet&, uint32_t& len) {
        len = 0; return nullptr;
    };
    virtual bool HasPayload() { return false; }

    uint16_t Checksum(const CheckField*);

    const char* SrcAddr(const Packet&);
    const char* DstAddr(const Packet&);

    uint16_t SrcPort(const Packet&);
    uint16_t DstPort(const Packet&);

    void SetPeer(Protocol* p) { peer = p; };
    Protocol* GetPeer() { return peer; };

protected:
    Protocol(const char* s) { type = s; };

private:
    string type;
    Protocol* peer;
};

// never enabled externally
#undef __PROTOTOOL_TAG__

// every protocol subclass header must
// include 4 lines like the following:
// (only the xyz parts change)
#ifdef __PROTOTOOL_TAG__
#include "xyz.h"
PROTOTOOL_NEW(XyzProtocol);
#endif

#endif

