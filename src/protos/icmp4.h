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
// icmp4 stuff
//-------------------------------------------------------------------------

#ifndef __ICMP4_H__
#define __ICMP4_H__

#include "protocol.h"

class Icmp4Protocol : public Protocol {
public:
    Icmp4Protocol();
    ~Icmp4Protocol() override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;

    static class Pimp* GetPimp();

protected:
    virtual void Checksum(const Packet&);

private:
    class Icmp4Impl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "icmp4.h"
PROTOTOOL_NEW(Icmp4Protocol);
#endif

#endif

