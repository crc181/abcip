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
// abcip stuff
//-------------------------------------------------------------------------

#ifndef __ABC_IP_H__
#define __ABC_IP_H__

#include "user.h"
#include "writer.h"

class AbcIp {
public:
    AbcIp(const char* stk, const char* user, Writer* = NULL);
    virtual ~AbcIp();

    bool AtoB();
    bool BtoA();

    bool Configure();

    class Cake& GetCake(bool a2b);
    unsigned GetLayer(const string&, bool a2b);

    const string& GetProtocol(unsigned lyr, bool a2b);
    const string& GetRootId();

private:
    class AbcIpImpl* my;
};

#endif

