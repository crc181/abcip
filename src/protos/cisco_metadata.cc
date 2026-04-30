//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2022-2022 Ron Dempster
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
// cisco metadata stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cisco_metadata.h"

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__darwin__) || defined(__OpenBSD__)
#include <sys/types.h>
#endif

#include <arpa/inet.h>

#include "cake.h"
#include "eth.h"
#include "field.h"
#include "packet.h"
#include "pimp.h"

using namespace std;

static const char* s_type = "cisco";

// placing pid last allows normal chaining / encapsulation
// instead of making this an optional part of the eth header
//
struct CiscoMetadataHdr {
    uint8_t version;
    uint8_t length;
    uint16_t options;
    uint16_t sgt;
    uint16_t pid;
};

class CiscoMetadataImpl {
public:
    CiscoMetadataHdr h;
};

CiscoMetadataProtocol::CiscoMetadataProtocol () : Protocol(s_type) {
    my = new CiscoMetadataImpl;
}

CiscoMetadataProtocol::~CiscoMetadataProtocol () {
    delete my;
}

bool CiscoMetadataProtocol::Bind (const string& type) {
    uint16_t et;

    if ( !EthProtocol::GetBinding(type, et) )
        return false;

    my->h.pid = htons(et);
    return true;
}

void CiscoMetadataProtocol::Store (Cake& cake, bool a2b) {
    cake.Store("sgt", "1", true);
    Protocol::Store(cake, a2b);
}

const uint8_t* CiscoMetadataProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    if ( p.cake.IsSet("pid") )
        my->h.pid = htons((uint16_t)p.cake.GetValue("pid", 0));

    uint16_t sgt = (uint16_t)p.cake.GetValue("sgt", 0);

    my->h.version = 1;
    my->h.length = 1;
    my->h.options = htons(1);
    my->h.sgt = htons(sgt);

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "sgt", "u16", "set sgt" },
    { FT_PKT, "pid", "u16", "set protocol id" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class CiscoMetadataPimp : public Pimp {
public:
    CiscoMetadataPimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new CiscoMetadataProtocol();
    }

    void HelpBind(ostream&) override;
};

void CiscoMetadataPimp::HelpBind (ostream& out) {
    out << Type() << " -> " << EthProtocol::GetBindings() << endl;
}

Pimp* CiscoMetadataProtocol::GetPimp () { return new CiscoMetadataPimp; }

