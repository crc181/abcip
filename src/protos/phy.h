//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2011-2017 Charles R. Combs
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
// phy stuff
//-------------------------------------------------------------------------

#ifndef __PHY_H__
#define __PHY_H__

#include "protocol.h"

class PhyProtocol : public Protocol {
public:
    PhyProtocol();
    ~PhyProtocol() override;

    void Fetch(Cake&, bool) override;

    bool Bind(const std::string&) override;
    const uint8_t* GetHeader(Packet&, uint32_t&) override;
    const uint8_t* GetPayload(const Packet&, uint32_t&) override;

    bool HasPayload() override;
    static class Pimp* GetPimp();

private:
    void FetchA2B(Cake&);
    void FetchB2A(Cake&);

private:
    struct PhyImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "phy.h"
PROTOTOOL_NEW(PhyProtocol);
#endif

#endif

