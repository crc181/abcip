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
// commandparser stuff
//-------------------------------------------------------------------------

#ifndef __CMD_PARSER_H__
#define __CMD_PARSER_H__

#include "parser.h"

class CommandParser : public Parser {
public:
    CommandParser(class Reader*, const char*);
    virtual ~CommandParser();

    virtual bool Load(Command&);
    virtual bool Good();
    virtual void GetLocation(int& y, int& x);

private:
    class CommandParserImpl* my;
};

#endif

