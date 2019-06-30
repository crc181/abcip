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

#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <net/ethernet.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX
#include <netinet/ether.h>
#endif

#include "field.h"
#include "status.h"

ostream& operator<< (ostream& os, const Field& f) {
    os << f.name;
    os << " (" << f.type << ") ";
    os << f.help;
    return os;
}

FieldType Field::GetType (const string& cmd) {
    if ( cmd == "a" || cmd == "b" )
        return FT_PKT;

    if ( cmd == "c" )
        return FT_CFG;

    if ( cmd == "d" )
        return FT_DEF;

    return FT_MAX;
}

void Field::Print (
    ostream& out, FieldType ft, string& t, const Field* f
) {
    while ( f && f->name )
    {
        if ( ft == f->use )
            out << t << ":" << *f << endl;
        ++f;
    }
}

//---------------------------------------------------------------------

static bool ValidString (const char* s, bool quotes) {
    unsigned n = strlen(s);

    if ( !quotes ) {
        status.SetError("not a string");
        return false;
    }
    if ( !n ) {
        status.SetError("empty string");
        return false;
    }
    return true;
}

static bool ValidIp4 (const char* s) {
    struct in_addr buf;

    if ( inet_pton(AF_INET, s, &buf) <= 0 ) {
        status.SetError("bad ip4 address");
        return false;
    }
    return true;
}

static bool ValidIp6 (const char* s) {
    struct in6_addr buf;

    if ( inet_pton(AF_INET6, s, &buf) <= 0 ) {
        status.SetError("bad ip6 address");
        return false;
    }
    return true;
}

static bool ValidMac (const char* s) {
    if ( !ether_aton(s) ) {
        status.SetError("bad mac address");
        return false;
    }
    return true;
}

static bool ValidBool (const char*) {
    // FIXTHIS should have no value?
    // allow 0|1, true|false too?
    return true;
}

static bool ValidInt (const char* s, int max) {
    // this is unfortunate but some vars can
    // be an int and/or a flag; eg tcp:ack
    if ( !strcmp(s, " ") )
        return true;

    char* end = nullptr;
    long ret = (long)strtol(s, &end, 0);

    if ( !*s || *end ) {
        status.SetError("not a whole number");
        return false;
    }
    if ( ret >= (1L << max) ) {
        status.SetError("out of range");
        return false;
    }
    return true;
}

static bool ValidFloat (const char* s) {
    char* end;
    strtod(s, &end);

    if ( !*s || *end ) {
        status.SetError("not a real number");
        return false;
    }
    return true;
}

//---------------------------------------------------------------------
// these are the various types currently specified:
// a16 a4 a6
// b i32 r32 s*
// u1 u12 u13 u16 u2 u20 u3 u32 u4 u8
// u32|max

static bool Validate (const char* type, const string& val) {
    if ( !type || val.empty() )
        return false;

    string tmp = val;
    bool quotes = false;

    // tokens are returned with any quotes which
    // are stripped when stored - validation is
    // before storage
    if ( tmp[0] == '"' && tmp[tmp.size()-1] == '"' ) {
        tmp.erase(0, 1);
        tmp.erase(tmp.size()-1,1);
        quotes = true;
    }
    const char* s = tmp.c_str();

    if ( !strcasecmp(type, "s*") )
        return ValidString(s, quotes);

    if ( !strcasecmp(type, "a4") )
        return ValidString(s, quotes) && ValidIp4(s);

    if ( !strcasecmp(type, "a6") )
        return ValidString(s, quotes) && ValidMac(s);

    if ( !strcasecmp(type, "a16") )
        return ValidString(s, quotes) && ValidIp6(s);

    if ( !strcasecmp(type, "b") )
        return ValidBool(s);

    if ( tolower(*type) == 'u' ) {
        if ( strstr(type, "max") && !strcmp(s, "max") )
            return true;

        return ValidInt(s, atoi(type+1));
    }
    if ( tolower(*type) == 'i' )
        return ValidInt(s, atoi(type+1));

    if ( tolower(*type) == 'r' )
        return ValidFloat(s);

    return false;
}

//---------------------------------------------------------------------
// TBD - add range to Field for better validation?
// TBD - use quicker looker lookup than linear search
// TBD - refactor validation (into access?) to avoid
//       converting twice

bool Field::Validate (
    const Field* f, FieldType ft,
    const string& key, const string& val
) {
    while ( f->name ) {
        if ( f->use == ft && f->name == key )
            return ::Validate(f->type, val);
        f++;
    }
    // can't set error if not found because multiple field
    // arrays are inspected (proto specific, proto generic,
    // and users) individually.
    return false;
}

