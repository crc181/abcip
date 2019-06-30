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
// stream_reader stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_reader.h"

#include <fstream>

using namespace std;

StreamReader::StreamReader (const char* filename) {
    const string dev = "tty";

    if ( filename && filename != dev )
        sin = new ifstream(filename);
    else
        sin = &cin;

    *sin >> noskipws;
}

StreamReader::StreamReader (istream* is) {
    sin = is;
}

StreamReader:: ~StreamReader() {
    if ( sin != &cin )
        delete sin;
}

bool StreamReader::operator>> (char& c) {
    return static_cast<bool>( *sin >> c );
}

