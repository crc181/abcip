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
// protocol stuff
//-------------------------------------------------------------------------

#include <stdlib.h>

#include "pimp.h"
#include "status.h"

//-------------------------------------------------------------------------
// help for base level attributes

Pimp::Pimp (const char* s, const Field* f)
    { type = s; fields = f; }

static Field s_fields[] = {
    { FT_PKT, "head", "s*", "set header octets" },
    { FT_PKT, "tail", "s*", "set trailer octets" },
    { FT_MAX, NULL, NULL, NULL }
};

void Pimp::HelpPacket (ostream& out) {
    Field::Print(out, FT_PKT, type, s_fields);
    Field::Print(out, FT_PKT, type, fields);
}

void Pimp::HelpConfig (ostream& out) {
    Field::Print(out, FT_CFG, type, fields);
}

bool Pimp::Validate (
    FieldType ft, const string& key, const string& val
) {
    if ( Field::Validate(fields, ft, key, val) )
        return true;

    if ( !status.Ok() )
        return false;

    return Field::Validate(s_fields, ft, key, val);
}

