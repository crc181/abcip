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
// parsing stuff
//-------------------------------------------------------------------------

#include <iostream>

//#include <string.h>
//#include <stdlib.h>

#include "attribute.h"
#include "data_parser.h"
#include "command.h"
#include "reader.h"

//-------------------------------------------------------------------------
// parser
//-------------------------------------------------------------------------

class DataParserImpl {
public:
    bool ok;
    string name, key;
    Reader* reader;
    int line, pos;
};

DataParser::DataParser (Reader* in, const char* n, const char* k) {
    my = new DataParserImpl;
    my->reader = in;
    my->name = n;
    my->key = k;
    my->line = my->pos = 0;
} 

DataParser::~DataParser () {
    delete my->reader;
    delete my;
}

bool DataParser::Good () {
    return my->ok;
}

void DataParser::GetLocation (int& y, int& x) {
    y = my->line;
    x = my->pos;
}

bool DataParser::Load (Command& cmd) {
    string tok, proto, ack = "ack", flag = "1";
    unsigned index = 4;
    char c;

    my->ok = true;
    ++my->line;
    my->pos = 0;

    while ( *my->reader >> c ) {
        if ( c == '\n' ) {
            break;
        }
        tok += c;
        ++my->pos;
    }
    if ( tok.size() ) {
        cmd.SetName(my->name);
        cmd.AddOption(new Option(index, my->key, tok, proto));
        cmd.AddOption(new Option(index, ack, flag, proto));
        return true;
    }
    return false;
}

