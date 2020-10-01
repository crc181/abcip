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
// dumb user stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dumb_user.h"

#include <fstream>
#include <sstream>

#include "data.h"
#include "field.h"
#include "packet.h"

using namespace std;

class DumbUserImpl {
public:
    istream* stream;
    string pay;
};

DumbUser::DumbUser () {
    my = new DumbUserImpl;
    my->stream = new istringstream(GetData());
    *my->stream >> noskipws;
}

DumbUser::~DumbUser () {
    delete my->stream;
    delete my;
}

//-------------------------------------------------------------------------

static const Field s_fields[] = {
    { FT_CFG, "a.data", "s*", "set user a stream" },
    { FT_CFG, "b.data", "s*", "set user b stream" },
    { FT_CFG, "a.file", "s*", "load user a stream from file" },
    { FT_CFG, "b.file", "s*", "load user b stream from file" },
    { FT_CFG, "a.reset", "u1", "reset user a state" },
    { FT_CFG, "b.reset", "u1", "reset user b state" },
    { FT_PKT, "pay", "s*", "set payload octets" },
    { FT_PKT, "data", "s*", "alias for pay" },
    { FT_PKT, "len", "u32|max", "set payload length" },
    { FT_PKT, "fill", "u16", "fill payload with seq%256" },
    { FT_PKT, "jump", "i32", "seq delta" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

void DumbUser::HelpConfig (ostream& out) {
    string s = "user";
    Field::Print(out, FT_CFG, s, s_fields);
}

void DumbUser::HelpPacket (ostream& out) {
    string s = "user";
    Field::Print(out, FT_PKT, s, s_fields);
}

// ideally, users would be handled as just another protocol layer
// for validation by Pimp but they do serve different purposes
// it may make sense to refactor validation if another user type
// is added
bool DumbUser::Validate (
    const string& cmd, const string& key, const string& val
) {
    FieldType ft = Field::GetType(cmd);
    return Field::Validate(s_fields, ft, key, val);
}

//-------------------------------------------------------------------------

void DumbUser::Setup (const char* id) {
    Cake& cake = GetCake();
    cake.SetLayer();

    string s = id;
    s += ".reset";

    if ( cake.IsSet(s) )
        my->stream->seekg(0, ios::beg);

    s = id;
    s += ".data";

    if ( cake.IsSet(s) ) {
        delete my->stream;
        s = cake.GetValue(s.c_str());
        my->stream = new istringstream(s);
    }
    s = id;
    s += ".file";

    if ( cake.IsSet(s) ) {
        delete my->stream;
        s = cake.GetValue(s.c_str());
        my->stream = new ifstream(s.c_str(), ios::binary);
    }
    *my->stream >> noskipws;

    bool ok = my->stream->good();

    if ( ok ) {
        streampos pos = my->stream->tellg();
        my->stream->seekg(0, my->stream->end);
        ok = my->stream->tellg() > 0;
        my->stream->seekg(pos);
    } else {
        delete my->stream;
        my->stream = new istringstream(GetData());
        *my->stream >> noskipws;
    }
}

//-------------------------------------------------------------------------

const uint8_t* DumbUser::Send (Packet& p, uint32_t& len) {
    const string& slen = p.cake.GetValue("len");

    if ( slen == "max" )
    {
        streampos pos = my->stream->tellg();
        my->stream->seekg(0, my->stream->end);
        len = my->stream->tellg();
        my->stream->seekg(pos);
    }
    else
        len = p.cake.GetValue("len", 0);

    my->pay = p.cake.GetValue("pay");

    if ( !my->pay.length() )
        my->pay = p.cake.GetValue("data");

    int32_t jump = p.cake.GetValue("jump", (int32_t)0);

    // no attempt is made to wrap on jump
    if ( jump ) {
        my->stream->seekg(jump, ios::cur);
        my->stream->clear();
    }

    if ( len ) {
        if ( my->pay.empty() ) {
            while ( my->pay.length() < len ) {
                // this could be a little smarter
                char b = 0;
                *my->stream >> b;
                if ( my->stream->eof() ) {
                    my->stream->clear();
                    my->stream->seekg(0, ios::beg);
                    *my->stream >> b;
                }
                my->pay += b;
            }
        }
    } else if ( !my->pay.empty() ) {
        len = my->pay.length();

    } else {
        len = p.cake.GetValue("fill", 0);

        for ( unsigned i = 0; i < len; i++ ) {
            char b = (char)(i) % 256;
            my->pay += b;
        }
    }
    return (const uint8_t*)my->pay.data();
}

void DumbUser::Recv (Packet&) { }

