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
// abcip stuff
//-------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>

#include "abc_ip.h"
#include "pile.h"
#include "user.h"
#include "writer.h"
#include "packet.h"
#include "parser.h"
#include "status.h"

#include "../protos/protocol.h"
#include "../protos/prototool.h"

using namespace std;

//-------------------------------------------------------------------------

class AbcIpImpl {
public:
    bool Setup(const char* stk, Pile*, User*, bool a2b);
    void Link();

    void Generate(Packet&, Pile*, bool a2b);
    void Respond(bool a2b);

public:
    Pile* sa, *sb;
    User* ua, *ub;
    Writer* writer;
};

AbcIp::AbcIp (
    const char* stk, const char* user, Writer* log
) {
    my = new AbcIpImpl;
    my->writer = log;

    my->ua = User::New(user);
    my->ub = User::New(user);
    my->sa = new Pile(*my->ua);
    my->sb = new Pile(*my->ub);

    if ( my->Setup(stk, my->sa, my->ua, true) &&
         my->Setup(stk, my->sb, my->ub, false) )
        my->Link();
    else
        status.SetError();
}

AbcIp::~AbcIp () {
    my->sa->PopAll();
    my->sb->PopAll();

    delete my->sa;
    delete my->sb;
    delete my->ua;
    delete my->ub;
    delete my;
}

//-------------------------------------------------------------------------
// public methods

Cake& AbcIp::GetCake (bool a2b) {
    return a2b ? my->ua->GetCake() : my->ub->GetCake();
}

unsigned AbcIp::GetLayer (const string& s, bool a2b) {
    Pile* stack = a2b ? my->sa : my->sb;
    return stack->GetLayer(s);
}

static const string s_err = "error";

const string& AbcIp::GetProtocol (unsigned lyr, bool a2b) {
    Pile* stack = a2b ? my->sa : my->sb;
    Protocol* p = stack->GetProtocol(lyr);
    return p ? p->GetType() : s_err;
}

const string& AbcIp::GetRootId () {
    return my->sa->GetRootId();
}

bool AbcIp::AtoB () {
    Packet pkt(my->ua->GetCake());
    my->Generate(pkt, my->sa, true);
    return true;
}

bool AbcIp::BtoA () {
    Packet pkt(my->ub->GetCake());
    my->Generate(pkt, my->sb, false);
    return true;
}

bool AbcIp::Configure () {
    Cake& ca = my->ua->GetCake();
    Cake& cb = my->ub->GetCake();

    unsigned layer = ca.GetLayer();

    while ( layer > 1 ) {
        ca.SetLayer(layer);
        cb.SetLayer(layer);

        string addr = ca.GetValue("a");

        if ( addr.size() ) {
            ca.Set("src", addr);
            cb.Set("dst", addr);
        }
        addr = ca.GetValue("b");

        if ( addr.size() ) {
            ca.Set("dst", addr);
            cb.Set("src", addr);
        }
        --layer;
    }
    ca.SetLayer();
    cb.SetLayer();

    my->ua->Setup("a");
    my->ub->Setup("b");

    my->sa->Configure(ca, true);
    my->sb->Configure(cb, false);

    return true;
}

//-------------------------------------------------------------------------
// private methods

#define SEP ':'

void AbcIpImpl::Link () {
    unsigned lyr = 1;
    unsigned max = ua->GetCake().GetTopLayer();

    Protocol* pa = sa->GetProtocol(lyr);
    Protocol* pb = sb->GetProtocol(lyr);

    while ( pa && pb ) {
        pa->SetPeer(pb);
        pb->SetPeer(pa);

        if ( lyr++ == max )
            break;

        pa = sa->GetProtocol(lyr);
        pb = sb->GetProtocol(lyr);
    }
}

bool AbcIpImpl::Setup (
    const char* stk, Pile* stack, User* usr, bool a2b
) {
    // automatically put the phy layer on bottom
    string stks;
    if ( strncasecmp(stk, "phy:", 4) ) {
        stks = "phy:";
        stks += stk;
        stk = stks.c_str();
    }
    const char* tok = stk;

    int layers = 1;  // first layer + number of SEP
    while ( *tok ) if ( *tok++ == SEP ) layers++;
    usr->GetCake().Restart(layers);

    Protocol* prev = NULL;
    tok = stk;

    while ( *tok ) {
        string s;

        while ( *tok && *tok != SEP )
            s += tolower(*tok++);

        PseudoHdr* ph = stack->GetPseudoHdr();
        Protocol* curr = ProtoTool::New(s, ph);

        if ( !curr ) {
            status.SetError("unknown proto");
            cerr << status << " (" << s << ")" << endl;
            return false;
        }
        stack->Push(curr, a2b);

        if ( prev ) {
            if ( !prev->Bind(curr->GetType()) ) {
                status.SetError();
                cerr << status << "can't bind " << curr->GetType();
                cerr << " to " << prev->GetType() << endl;
                return false;
            }
        }
        prev = curr;
        if ( *tok ) tok++;
    }    
    //usr->GetCake().Dump();
    return true;
}

void AbcIpImpl::Generate (
    Packet& pkt, Pile* stack, bool a2b
) {
    stack->Send(pkt);

    if ( pkt.Length() && !pkt.drop && writer )
        *writer << pkt;

    Respond(a2b);
    pkt.drop = false;

    do {
        stack->Flush(pkt);

        if ( !pkt.Length() )
            break;

        if ( !pkt.drop && writer )
            *writer << pkt;

        Respond(a2b);
    }
    while ( true );
}

void AbcIpImpl::Respond (bool a2b) {
    Pile* stack = a2b ? sb : sa;
    Cake& cake = a2b ? ub->GetCake() : ua->GetCake();
    Packet rsp(cake);

    stack->Flush(rsp);

    if ( rsp.Length() && !rsp.drop && writer )
        *writer << rsp;
}

