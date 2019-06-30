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
// dumb user stuff
//-------------------------------------------------------------------------

#ifndef __DUMB_USER_H__
#define __DUMB_USER_H__

#include "user.h"

class DumbUser : public User {
public:
    DumbUser();
    ~DumbUser() override;

    void Setup(const char* id) override;

    const uint8_t* Send(Packet&, uint32_t&) override;
    void Recv(Packet&) override;

    static const char* Type() { return "user"; };

    static void HelpConfig(ostream&);
    static void HelpPacket(ostream&);

    static bool Validate(const string&, const string&, const string&);

private:
    class DumbUserImpl* my;
};

#endif

