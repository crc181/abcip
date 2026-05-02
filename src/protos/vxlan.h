//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2026 Charles R. Combs
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
// vxlan stuff
//-------------------------------------------------------------------------

#ifndef __VXLAN_H__
#define __VXLAN_H__

#include "protocol.h"

class VxlanProtocol : public Protocol {
public:
    VxlanProtocol();
    ~VxlanProtocol() override;

    void Fetch(Cake&, bool) override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;

    static class Pimp* GetPimp();

private:
    class VxlanImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "vxlan.h"
PROTOTOOL_NEW(VxlanProtocol);
#endif

#endif
