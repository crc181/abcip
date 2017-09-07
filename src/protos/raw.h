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
// raw stuff
//-------------------------------------------------------------------------

#ifndef __RAW_H__
#define __RAW_H__

#include "protocol.h"

class RawProtocol : public Protocol {
public:
    RawProtocol();
    virtual ~RawProtocol();

    virtual bool Bind(const string&);
    virtual const uint8_t* GetHeader(Packet&, uint32_t&);

    static Pimp* GetPimp();

private:
    class RawImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "raw.h"
PROTOTOOL_NEW(RawProtocol);
#endif

#endif

