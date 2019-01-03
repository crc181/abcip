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
// abcio stuff
//-------------------------------------------------------------------------

#ifndef __ABC_IO_H__
#define __ABC_IO_H__

#include <iostream>
using namespace std;

class Parser;
class Writer;

class AbcIo {
public:
    AbcIo(Parser*, Writer*,
        const char* stk, const char* user, bool trace);
    virtual ~AbcIo();

    int Execute(int maxPkts = 0);
    void Interrupt();

    static void HelpDefine(ostream&);

private:
    class AbcIoImpl* my;
};

#define DEFAULT_STACK "eth:ip4:tcp"
#define DEFAULT_USER  "user"

#endif

