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

#include <iostream>
#include <string>

using namespace std;

//-------------------------------------------------------------------------
// pimp = protocol instantiation and management pattern
// (similar to a person in the management profession)
//-------------------------------------------------------------------------

#ifndef __PIMP_H__
#define __PIMP_H__

#include "field.h"

class Protocol;
class PseudoHdr;

class Pimp {
public:
    virtual ~Pimp() { };

    const string& Type() { return type; };

    virtual Protocol* New(PseudoHdr*) = 0;

    virtual void HelpBind(ostream&) { };

    void HelpConfig(ostream&);
    void HelpPacket(ostream&);

    bool Validate(FieldType, const string& key, const string& val);

protected:
    Pimp(const char* s, const Field*);

    void HelpConfig(ostream&, const Field*);
    void HelpPacket(ostream&, const Field*);

private:
    string type;
    const Field* fields;
};

#endif

