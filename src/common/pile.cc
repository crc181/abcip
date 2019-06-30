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
// pile stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pile.h"

#include <vector>

#include "cake.h"
#include "protocol.h"
#include "pseudo_hdr.h"
#include "user.h"

using namespace std;

typedef vector<Protocol*> ProtoList;

class PileImpl {
public:
    PileImpl(User& a) : user(a) { }

    ProtoList protos;
    PseudoHdr* ph;

    User& user;

    void Generate(Packet&, ProtoList::iterator&);
};

Pile::Pile (User& a) {
    my = new PileImpl(a);
    my->ph = nullptr;
}

Pile::~Pile () {
    delete my;
}

const string& Pile::GetRootId () {
    Protocol* pro = my->protos.front();
    if ( pro )
        return pro->GetType();

    static string dummy = "err";
    return dummy;
}

PseudoHdr* Pile::GetPseudoHdr () {
    return my->ph;
}

Protocol* Pile::GetProtocol (unsigned lyr) {
    return my->protos[lyr-1];
}

unsigned Pile::GetLayer (const string& s) {
    ProtoList::iterator it = my->protos.end();

    while ( it != my->protos.begin() ) {
        if ( (*--it)->GetType() == s )
            return it - my->protos.begin() + 1;
    }

    return 0;
}

void Pile::Push (Protocol* pro, bool a2b) {
    my->protos.push_back(pro);

    pro->Store(my->user.GetCake(), a2b);

    // this is the same on both ends
    unsigned lyr = my->user.GetCake().GetLayer();
    PseudoHdr* ph = pro->GetPseudoHdr(lyr);

    // only change if not null
    if ( ph )
        my->ph = ph;

    my->user.GetCake().Next();
}

void Pile::PopAll () {
    for ( ProtoList::iterator it = my->protos.begin();
        it != my->protos.end(); ++it )
        delete *it;

    my->protos.clear();
    my->user.GetCake().SetLayer(0);
}

void Pile::Configure (Cake& cake, bool a2b) {
    cake.SetFirstLayer();
    ProtoList::iterator it = my->protos.begin();

    while ( it != my->protos.end() ) {
        (*it)->Fetch(cake, a2b);
        cake.Next();
        it++;
    }
}

// assemble from top down
void Pile::Send (Packet& p) {
    uint32_t n;
    const uint8_t* h;

    p.Zero();
    p.cake.SetLastLayer();

    h = my->user.Send(p, n);
    p.Prepend(h, n);

    ProtoList::iterator it = my->protos.end();
    my->Generate(p, it);
}

// look for data from bottom up
// then assemble from there down
void Pile::Flush (Packet& p) {
    p.Zero();
    p.cake.SetFirstLayer();

    ProtoList::iterator it = my->protos.begin();

    while ( it != my->protos.end() ) {
        if ( (*it)->HasPayload() )
            break;
        p.cake.Next();
        ++it;
    }

    if ( it != my->protos.end() )
        my->Generate(p, ++it);
}

void PileImpl::Generate (
    Packet& p, ProtoList::iterator& it
) {
    while ( it != protos.begin() ) {
        --it;

        if (
            p.Length() ||
            (*it)->HasPayload() ||
            !p.cake.EmptyLayer()
        ) {
            uint32_t n;
            const uint8_t* h;

            h = (*it)->GetTrailer(p, n);
            p.Append(h, n);

            h = (*it)->GetPayload(p, n);

            if ( h ) {
                p.Zero();
                p.Prepend(h, n);
            }

            h = (*it)->GetOptions(p, n);
            p.Prepend(h, n);

            h = (*it)->GetHeader(p, n);
            p.Prepend(h, n);
        }
        p.cake.Prev();
    }
}

