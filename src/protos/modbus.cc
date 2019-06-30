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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modbus.h"

#include <cstdio>
#include <ostream>

#include "cake.h"

static const char* s_type = "modbus";

struct ModbusHdr {
    uint16_t transactionID;
    uint16_t protocolID;
    uint16_t length;
    uint8_t unitID;
    uint8_t func;
};

class ModbusImpl {
public:
    ModbusHdr h;
};

ModbusProtocol::ModbusProtocol() : Protocol(s_type)
{
    my = new ModbusImpl;
}

ModbusProtocol::~ModbusProtocol ()
{
    delete my;
}

const uint8_t* ModbusProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.transactionID = htons((uint16_t)p.cake.GetValue("tid", 1));
    my->h.protocolID = htons((uint16_t)p.cake.GetValue("pid", 0));
    my->h.length = htons((uint16_t)p.cake.GetValue("plen", p.Length() + 2));

    my->h.unitID = (uint8_t)p.cake.GetValue("uid", 255);
    my->h.func = (uint8_t)p.cake.GetValue("func", 1);

    len = sizeof(my->h);
    return (uint8_t*) & my->h;
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_PKT, "tid", "u16", "set transaction id" },
    { FT_PKT, "pid", "u16", "set protocol id" },
    { FT_PKT, "plen", "u16", "set modbus pdu length" },
    { FT_PKT, "uid", "u8", "set unit id" },
    { FT_PKT, "func", "u8", "set function code" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

class ModbusPimp : public Pimp {
public:
    ModbusPimp() : Pimp(s_type, s_fields) { }

    Protocol* New(PseudoHdr*) override {
        return new ModbusProtocol();
    }
};

Pimp* ModbusProtocol::GetPimp ()
{
    return new ModbusPimp;
}

