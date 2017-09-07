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
// attribute stuff
//-------------------------------------------------------------------------

#include <ostream>
using namespace std;

#include <stdlib.h>
#include "attribute.h"

int32_t Attribute::GetValue (int32_t dflt) {
    char* end;
    const char* s = value.c_str();
    uint32_t ret = strtol(s, &end, 0);
    return (*s && !*end) ? ret : dflt;
}

uint32_t Attribute::GetValue (uint32_t dflt) {
    char* end;
    const char* s = value.c_str();
    uint32_t ret = strtoul(s, &end, 0);
    return (*s && !*end) ? ret : dflt;
}

double Attribute::GetReal (double dflt) {
    char* end;
    const char* s = value.c_str();
    double ret = strtod(s, &end);
    return (*s && !*end) ? ret : dflt;
}

static inline uint8_t Hex(char c) {
    return isdigit(c) ? c-'0' : 10+(tolower(c)-'a');
}

bool Attribute::Compress (const string& sin) {
    unsigned i = 0, n = sin.length(), state = 0;
    uint8_t b = 0;
    value.clear();

    if ( i < n && sin[i] == '"' && sin[n-1] == '"' ) {
        i++;
        n--;
    }

    while ( i < n ) {
        switch ( state ) {
        case 0:
            if ( sin[i] == '\\' ) {
                state = 1;
            } else if ( sin[i] == '|' ) {
                state = 2;
            } else {
                value += sin[i];
            }
            break;

        case 1:
            value += sin[i];
            state = 0;
            break;

        case 2:
            if ( sin[i] == '|' ) {
                state = 0;
            } else if ( isxdigit(sin[i]) ) {
                b = Hex(sin[i]);
                state = 3;
            } else if ( !isspace(sin[i]) ) {
                return false;
            }
            break;

        case 3:
            if ( sin[i] == '|' ) {
                value += b;
                state = 0;
            } else if ( isxdigit(sin[i]) ) {
                b = (b << 4) | Hex(sin[i]);
                value += b;
                state = 2;
            } else if ( isspace(sin[i]) ) {
                value += b;
                state = 2;
            } else {
                return false;
            }
            break;
        }
        i++;
    }
    return ( state == 0 );
}

void Attribute::Expand (ostream& out) {
    bool text = true;
    out << '"';

    for (unsigned i = 0; i < value.length(); i++) {
        char c = value[i];

        if ( isprint(c) ) {
            if ( !text ) {
                out << '|';
                out << dec;
                text = true;
            }
            out << c;

        } else {
            if ( text ) {
                out << '|';
                out << hex;
                text = false;
            } else {
                out << " ";
            }
            out << (uint16_t)c;
        }
    }
    if ( !text ) out << '|';
    out << '"';
}

#if 0
bool Compress (string& s) {
    unsigned i = 0, state = 0;
    uint8_t b = 0;

    while ( i < s.length() ) {
        switch ( state ) {
        case 0:
            if ( s[i] == '\\' ) {
                state = 1;
                s.erase(i, 1);
            } else if ( s[i] == '|' ) {
                state = 2;
                s.erase(i, 1);
            } else {
                i++;
            }
            break;

        case 1:
            state = 0;
            i++;
            break;

        case 2:
            if ( s[i] == '|' ) {
                state = 0;
                s.erase(i, 1);
            } else if ( isxdigit(s[i]) ) {
                b = Hex(s[i]);
                state = 3;
                s.erase(i, 1);
            } else if ( isspace(s[i]) ) {
                s.erase(i, 1);
            } else {
                return false;
            }
            break;

        case 3:
            if ( s[i] == '|' ) {
                state = 0;
                s[i++] = b;
            } else if ( isxdigit(s[i]) ) {
                b = (b << 4) | Hex(s[i]);
                s[i++] = b;
                state = 2;
            } else if ( isspace(s[i]) ) {
                state = 2;
                s[i++] = b;
            } else {
                return false;
            }
            break;
        }
    }
    return ( state == 0 );
}

void PrintTCP (uint8_t u, string& s) {
    s = "UAPRSF";

    for ( int i = 0; i < 6; i++) 
        if ( !((1<<(5-i)) & u) ) s[i] = '-'; 
}

void PrintECN (uint8_t u, string& s) {
    s = "ECN";

    for ( int i = 0; i < 3; i++) 
        if ( !((1<<(2-i)) & u) ) s[i] = '-'; 
}
#endif

