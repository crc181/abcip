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
// ip6 stuff
//-------------------------------------------------------------------------

#ifndef __IP6_H__
#define __IP6_H__

#include "protocol.h"

class Ip6Protocol : public Protocol {
public:
    Ip6Protocol();
    ~Ip6Protocol() override;

    void Store(Cake&, bool) override;
    bool Bind(const std::string&) override;

    PseudoHdr* GetPseudoHdr(unsigned lyr) override;
    const uint8_t* GetHeader(Packet&, uint32_t&) override;

    static Pimp* GetPimp();
    static const char* GetBindings();
    static bool GetBinding(const std::string& s, uint8_t& et);

private:
    class Ip6Impl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "ip6.h"
PROTOTOOL_NEW(Ip6Protocol);
#endif

#endif

