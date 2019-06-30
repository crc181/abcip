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
// parser stuff
//-------------------------------------------------------------------------

#ifndef __PARSER_H__
#define __PARSER_H__

class Parser {
public:
    virtual ~Parser() = default;

    virtual bool Load(class Command&) = 0;
    virtual bool Good() = 0;
    virtual void GetLocation(int& y, int& x) = 0;

protected:
    Parser() = default;
};

#endif

