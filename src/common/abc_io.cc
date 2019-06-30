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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "abc_io.h"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <map>

#include "abc_ip.h"
#include "cake.h"
#include "command.h"
#include "field.h"
#include "parser.h"
#include "prototool.h"
#include "status.h"
#include "writer.h"

using namespace std;

#define CMD_A2B "a"
#define CMD_B2A "b"
#define CMD_CFG "c"
#define CMD_DEF "d"

#define DEFAULT_KEY "default"

typedef map<const string, AbcIp*> AbcMap;

class AbcIoImpl {
public:
    AbcIp* New(Command&);
    AbcIp* Find(Command&);
    AbcIp* Load(Command&);

    void Dump(Command&, unsigned n);
    bool SetVar(AbcIp*, Command&, Option*, bool);

public:
    AbcMap sessions;
    Parser* parser;
    Writer* writer;
    string stack;
    string user;
    bool trace;
    bool stop;
};

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_DEF, "stack", "s*", "define new stack" },
    { FT_MAX, nullptr, nullptr, nullptr }
};

void AbcIo::HelpDefine (ostream& out) {
    string type = "abc";
    Field::Print(out, FT_DEF, type, s_fields);
}

static const char* GetStack (Option* opt) {
    if ( Field::Validate(s_fields, FT_DEF, opt->key, opt->value) ) {
        opt->value.erase(opt->value.length()-1, 1);
        opt->value.erase(0, 1);
        return opt->value.c_str();
    }
    status.SetPos(opt->row, opt->col);
    cerr << status << " (" << opt->key;

    if ( opt->value != " " )
        cerr << "=" << opt->value;

    cerr << ")" << endl;
    return nullptr;
}

AbcIp* AbcIoImpl::New (Command& cmd) {
    string& ssn = cmd.GetContext();
    Option* opt = cmd.GetOption(0);
    const char* s = nullptr;

    if ( ssn.empty() )
        ssn.assign(DEFAULT_KEY);

    if ( opt ) {
        s = GetStack(opt);

        if ( !s )
            return nullptr;
    }
    if ( !s || !*s )
        s = stack.c_str();

    AbcIp* abc = sessions[ssn];

    if ( abc )
        delete abc;

    abc = new AbcIp(s, user.c_str(), writer);
    sessions[ssn] = abc;

    return abc;
}

//-------------------------------------------------------------------------

AbcIp* AbcIoImpl::Find (Command& cmd)
{
    string& key = cmd.GetContext();

    if ( key.empty() )
        key.assign(DEFAULT_KEY);

    AbcMap::iterator it = sessions.find(key);

    if ( it != sessions.end() )
        return it->second;

    if ( key != DEFAULT_KEY ) {
        status.SetError("undefined context");
        cerr << status << " (" << key << ")" << endl;
        return nullptr;
    }
    AbcIp* abc = new AbcIp(stack.c_str(), user.c_str(), writer);
    sessions[key] = abc;

    return abc;
}

//-------------------------------------------------------------------------

void AbcIoImpl::Dump (Command& cmd, unsigned n) {
    int i = 0;
    const Option* o = cmd[i++];

    cerr << n << ". ";
    cerr << cmd.GetContext() << ": ";
    cerr << cmd.GetName() << " ( ";

    while ( o ) {
        if ( i > 1 )
            cerr << ", "; // FIXTHIS may be "; "

        if ( o->index )
            cerr << o->index << ":";

        else if ( !o->proto.empty() )
            cerr << o->proto << ":";

        cerr << o->key;

        if ( o->value != " " )
            cerr << "=" << o->value;

        o = cmd[i++];
    }
    cerr << " ) " << endl;
}

//-------------------------------------------------------------------------

bool AbcIoImpl::SetVar (
    AbcIp* abc, Command& cmd, Option* opt, bool a2b
) {
    Cake& cake = abc->GetCake(a2b);

    if ( !opt->proto.empty() )
        opt->index = abc->GetLayer(opt->proto, a2b);

    if ( (int)opt->index < 0 )
        opt->index = cake.GetTopLayer() + (int)opt->index;

    if ( opt->index > cake.GetTopLayer() ) {
        status.SetError("invalid layer");
        return false;
    }
    cake.SetLayer(opt->index);

    unsigned layer = cake.GetLayer();
    const string& proto = abc->GetProtocol(layer, a2b);

    if ( ProtoTool::Validate(cmd.GetName(), proto, opt->key, opt->value) ) 
    {
        cake.Set(opt->key, opt->value);
        return true;
    }
    if ( layer == cake.GetTopLayer() &&
         User::Validate(cmd.GetName(), opt->key, opt->value) )
    {
        cake.Set(opt->key, opt->value);
        return true;
    }
    if ( status.Ok() )
        status.SetError("unknown var");

    return false;
}

//-------------------------------------------------------------------------

AbcIp* AbcIoImpl::Load (Command& cmd) {
    AbcIp* abc = Find(cmd);

    if ( !abc )
        return nullptr;

    int i = 0;
    Option* opt = cmd[i++];

    abc->GetCake(true).Reset();
    abc->GetCake(false).Reset();

    // FIXTHIS not all c vars must be set on both ends
    // (a.data etc. should only be set for a, not b)
    // FIXTHIS only validate on one end
    while ( opt ) {
        if ( cmd.GetName() != "a" ) {
            if ( !SetVar(abc, cmd, opt, false) )
                break;
        }
        if ( cmd.GetName() != "b" ) {
            if ( !SetVar(abc, cmd, opt, true) )
                break;
        }
        opt = cmd[i++];
    }
    if ( opt ) {
        status.SetPos(opt->row, opt->col);
        cerr << status << " (" << opt->key;

        if ( opt->value != " " )
            cerr << "=" << opt->value;

        cerr << ")" << endl;
        return nullptr;
    }
    return abc;
}

//-------------------------------------------------------------------------

AbcIo::AbcIo (
    Parser* parser, Writer* writer,
   const char* stack, const char* user, bool trace
) {
    my = new AbcIoImpl;
    my->parser = parser;
    my->writer = writer;
    my->trace = trace;
    my->stack = stack;
    my->user = user;
    my->stop = false;
}

AbcIo::~AbcIo () {
    AbcMap::iterator it;

    for ( it = my->sessions.begin(); it != my->sessions.end(); ++it )
        delete it->second;

    if ( my->writer )
        delete my->writer;

    delete my->parser;
    delete my;
}

void AbcIo::Interrupt () {
    my->stop = true;
}

//-------------------------------------------------------------------------

int AbcIo::Execute (int maxPkts) {
    Command cmd;
    unsigned numCmds = 0;
    int numPkts = 0;

    while ( maxPkts <= 0 || numPkts < maxPkts )
    {
        if ( my->stop )
        {
            my->stop = false;
            break;
        }

        if ( !my->parser->Load(cmd) )
            break;

        if ( my->trace )
            my->Dump(cmd, numCmds);

        bool ok = false;
        if ( cmd.GetName() == CMD_A2B ) {
            AbcIp* abc = my->Load(cmd);
            ok = abc && abc->AtoB();
            numPkts++;
        }
        else if ( cmd.GetName() == CMD_B2A ) {
            AbcIp* abc = my->Load(cmd);
            ok = abc && abc->BtoA();
            numPkts++;
        }
        else if ( cmd.GetName() == CMD_CFG ) {
            AbcIp* abc = my->Load(cmd);
            ok = abc && abc->Configure();
        }
        else if ( cmd.GetName() == CMD_DEF ) {
            AbcIp* abc = my->New(cmd);
            ok = abc && status.Ok();
        }
        if ( !ok )
            return -1;

        cmd.Clear();
        numCmds++;
    }
    if ( !status.Ok() )
        return -1;

    if ( !my->parser->Good() )
        return -1;

    return numCmds;
}

