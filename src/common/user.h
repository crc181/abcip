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
// user stuff
//-------------------------------------------------------------------------

#ifndef __USER_H__
#define __USER_H__

#include <string>

#include "cake.h"
#include "packet.h"

class User {
public:
    static User* New(const std::string&);
    virtual ~User() = default;

    virtual void Setup(const char* id) = 0;

    virtual const uint8_t* Send(Packet&, uint32_t&) = 0;
    virtual void Recv(Packet&) = 0;

    static void HelpTypes(std::ostream&);
    static void HelpConfig(std::ostream&);
    static void HelpPacket(std::ostream&);

    static bool Validate(const std::string&, const std::string&, const std::string&);

    Cake& GetCake() { return cake; }

protected:
    User() = default;

private:
    Cake cake;
};

#endif

