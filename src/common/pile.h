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
// pile stuff (protocol indexing and layering entity)
//-------------------------------------------------------------------------

#ifndef __PILE_H__
#define __PILE_H__

#include <string>

class User;

class Pile {
public:
    Pile(User&);
    virtual ~Pile();

    void Push(class Protocol*, bool a2b);
    void PopAll();

    const std::string& GetRootId();
    class PseudoHdr* GetPseudoHdr();

    class Protocol* GetProtocol(unsigned lyr);
    unsigned GetLayer(const std::string&);

    void Configure(class Cake&, bool a2b);

    void Send(class Packet&);
    void Flush(class Packet&);

private:
    class PileImpl* my;
};

#endif

