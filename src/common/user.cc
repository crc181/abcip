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
// user stuff
//-------------------------------------------------------------------------

#include "user.h"
#include "dumb_user.h"

using namespace std;

User* User::New (const string& s) {
    if ( DumbUser::Type() == s )
        return new DumbUser;

    return nullptr;
}

void User::HelpTypes (ostream& out) {
    out << "Available users:" << endl;
    out << DumbUser::Type() << endl;
}

void User::HelpConfig (ostream& out) {
    DumbUser::HelpConfig(out);
}

void User::HelpPacket (ostream& out) {
    DumbUser::HelpPacket(out);
}

bool User::Validate (
    const string& s, const string& k, const string& v
) {
    return DumbUser::Validate(s, k, v);
}

