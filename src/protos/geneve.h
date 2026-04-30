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
// geneve stuff
//-------------------------------------------------------------------------

#ifndef __GENEVE_H__
#define __GENEVE_H__

#include "protocol.h"

class GeneveProtocol : public Protocol {
public:
    GeneveProtocol();
    ~GeneveProtocol() override;

    bool Bind(const std::string&) override;
    void Fetch(Cake&, bool) override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;
    const uint8_t* GetOptions(const Packet&, uint32_t&) override;

    static class Pimp* GetPimp();

private:
    class GeneveImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "geneve.h"
PROTOTOOL_NEW(GeneveProtocol);
#endif

#endif
