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
// factory stuff
//
// it would be nice if the Pimp ctor could automatically register the
// protocol so that just by static declaration of Pimp subclasses within
// the various proto subclass modules the protocols could all be made
// available.  unfortunately, that gets into a static instantiation
// ordering issue which is undefined between modules, so we settle for
// some make magic to soft code the bindings.
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "prototool.h"

#include <map>

#include "pimp.h"
#include "protocol.h"
#include "status.h"

#include "prototool-inc.h"

using namespace std;

//-------------------------------------------------------------------------

typedef map<const string, Pimp*> ProtoMap;
static ProtoMap protos;

class ProtoMapper {
public:
    ProtoMapper();
    ~ProtoMapper();
};

static ProtoMapper pmap;

//-------------------------------------------------------------------------

#define PROTOTOOL_NEW(proto)    \
    do {                        \
        p = proto::GetPimp();   \
        protos[p->Type()] = p;  \
    } while (0)

ProtoMapper::ProtoMapper () {
    Pimp* p;

#include "prototool-new.h"
}

ProtoMapper::~ProtoMapper () {
    ProtoMap::iterator it;

    for ( it = protos.begin(); it != protos.end(); ++it )
        delete it->second;
}

//-------------------------------------------------------------------------

void ProtoTool::HelpTypes (ostream& out) {
    out << "Available protocols:" << endl;

    ProtoMap::iterator it;

    for ( it = protos.begin(); it != protos.end(); ++it ) {
        Pimp* h = it->second;
        cout << h->Type() << endl;
    }
}

void ProtoTool::HelpBind (ostream& out) {
    out << "Available bindings:" << endl;

    ProtoMap::iterator it;

    for ( it = protos.begin(); it != protos.end(); ++it )
        it->second->HelpBind(out);
}

void ProtoTool::HelpConfig (ostream& out) {
    ProtoMap::iterator it;

    for ( it = protos.begin(); it != protos.end(); ++it )
        it->second->HelpConfig(out);
}

void ProtoTool::HelpPacket (ostream& out) {
    ProtoMap::iterator it;

    for ( it = protos.begin(); it != protos.end(); ++it )
        it->second->HelpPacket(out);
}

//-------------------------------------------------------------------------

Protocol* ProtoTool::New (const string& s, PseudoHdr* ph) {
    ProtoMap::iterator it = protos.find(s);

    if ( it != protos.end() )
        return it->second->New(ph);

    return nullptr;
}

//-------------------------------------------------------------------------

bool ProtoTool::Validate (
    const string& cmd, const string& s,
    const string& key, const string& val
) {
    ProtoMap::iterator it = protos.find(s);
    FieldType ft = Field::GetType(cmd);

    if ( it != protos.end() )
        return it->second->Validate(ft, key, val);

    status.SetError("unknown protocol");
    return false;
}

