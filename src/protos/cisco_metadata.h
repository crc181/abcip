//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2022-2026 Ron Dempster
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

#ifndef __CISCO_METADATA_H__
#define __CISCO_METADATA_H__

#include "protocol.h"

class CiscoMetadataProtocol : public Protocol {
public:
    CiscoMetadataProtocol();
    ~CiscoMetadataProtocol() override;

    bool Bind(const std::string&) override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;

    void Store(Cake&, bool) override;

    static class Pimp* GetPimp();

private:
    class CiscoMetadataImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "cisco_metadata.h"
PROTOTOOL_NEW(CiscoMetadataProtocol);
#endif

#endif

