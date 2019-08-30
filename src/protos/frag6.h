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
// ip6 frag extension header
//-------------------------------------------------------------------------

#ifndef __FRAG6_H__
#define __FRAG6_H__

#include "protocol.h"

class Frag6Protocol : public Protocol {
public:
    Frag6Protocol();
    ~Frag6Protocol() override;

    bool Bind(const std::string&) override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;
    const uint8_t* GetPayload(const Packet&, uint32_t&) override;

    bool HasPayload() override;
    static class Pimp* GetPimp();

private:
    class Frag6Impl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "frag6.h"
PROTOTOOL_NEW(Frag6Protocol);
#endif

#endif

