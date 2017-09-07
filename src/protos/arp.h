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
// arp stuff
//-------------------------------------------------------------------------

#ifndef __ARP_H__
#define __ARP_H__

#include "protocol.h"

class ArpProtocol : public Protocol {
public:
    ArpProtocol();
    virtual ~ArpProtocol();

    virtual void Store(Cake&, bool);

    virtual const uint8_t* GetHeader(Packet&, uint32_t&);
    virtual const uint8_t* GetOptions(const Packet&, uint32_t&);

    static Pimp* GetPimp();

private:
    class ArpImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "arp.h"
PROTOTOOL_NEW(ArpProtocol);
#endif

#endif

