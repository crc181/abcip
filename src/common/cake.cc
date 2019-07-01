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
// cake stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cake.h"

#include <iostream>
#include <map>

#include "attribute.h"

using namespace std;

typedef map<string, Attribute> AttributeMap;

class CakeImpl {
public:
    AttributeMap* attribs;
    string null;
    unsigned layer, max;
};

// for simplicity we don't use layer 0
#define MIN 1

Cake::Cake (unsigned n) {
    my = new CakeImpl;
    my->attribs = nullptr;
    Restart(n);
}

Cake::~Cake () {
    delete[] my->attribs;
    delete my;
}

void Cake::Restart (unsigned n) {
    if ( !n ) n = MIN;
    if ( my->attribs ) delete[] my->attribs;
    my->attribs = new AttributeMap[n+1];
    my->max = n;
    my->layer = MIN;
}

unsigned Cake::GetTopLayer () {
    return my->max;
}

void Cake::SetFirstLayer () {
    my->layer = MIN;
}

void Cake::SetLastLayer () {
    my->layer = my->max;
}

bool Cake::SetLayer (unsigned n) {
    if ( !n ) n = my->max;
    if ( n < MIN || n > my->max )
        return false;
    my->layer = n;
    return true;
}

unsigned Cake::GetLayer () {
    return my->layer;
}

bool Cake::Next () {
    if ( my->layer == my->max )
        return false;
    my->layer++;
    return true;
}

bool Cake::Prev () {
    if ( my->layer == MIN )
        return false;
    my->layer--;
    return true;
}

void Cake::Store (const char* key, const char* val, bool icky) {
    AttributeMap& m = my->attribs[my->layer];
    Attribute& a = m[key];
    a.Set(val);
    a.SetSticky(icky);
}

void Cake::Dump () {
    for ( unsigned i = MIN; i <= my->max; i++ ) {
        AttributeMap::iterator it; 
        AttributeMap& m = my->attribs[i];

        for ( it = m.begin(); it != m.end(); ++it ) { 
            Attribute& a = it->second;
            cout << i << ": " << it->first;
            cout << "=";
            a.Print(cout);
            cout << endl;
        }
    }
}

void Cake::Reset () {
    for ( unsigned i = MIN; i <= my->max; i++ ) {
        AttributeMap::iterator it; 
        AttributeMap& m = my->attribs[i];

        for ( it = m.begin(); it != m.end(); ++it ) { 
            it->second.Reset();
        }
    }
    SetLayer();
}

void Cake::Reset (const char* s) {
    string name(s);
    AttributeMap& m = my->attribs[my->layer];
    AttributeMap::iterator it = m.find(name);

    if ( it != m.end() ) {
        Attribute& a = it->second;
        a.Reset();
    }
}

void Cake::Clear (const char* s) {
    string name(s);
    AttributeMap& m = my->attribs[my->layer];
    AttributeMap::iterator it = m.find(name);

    if ( it != m.end() ) {
        Attribute& a = it->second;
        a.Clear();
    }
}

bool Cake::EmptyLayer () {
    AttributeMap& m = my->attribs[my->layer];
    return m.empty();
}

bool Cake::IsSet (const char* s) {
    string key(s);
    return IsSet(key);
}

bool Cake::IsSet (string& key) {
    AttributeMap& m = my->attribs[my->layer];
    AttributeMap::iterator it = m.find(key);

    if ( it != m.end() ) {
        Attribute& a = it->second;
        return a.IsSet();
    }
    return false;
}

void Cake::Set (const string& key, const string& val) {
    AttributeMap& m = my->attribs[my->layer];
    Attribute& a = m[key];
    a.Set(val);
}

void Cake::Set (const char* key, const string& val) {
    AttributeMap& m = my->attribs[my->layer];
    Attribute& a = m[key];
    a.Set(val);
}

const char* Cake::GetCValue (const char* s) {
    return GetValue(s).c_str();
}

const string& Cake::GetValue (const char* s) {
    string name(s);
    AttributeMap& m = my->attribs[my->layer];
    AttributeMap::iterator it = m.find(name);

    if ( it != m.end() ) {
        Attribute& a = it->second;
        return a.GetValue();
    }
    return my->null;
}

uint32_t Cake::GetValue (const char* s, uint32_t dflt) {
    string name(s);
    AttributeMap& m = my->attribs[my->layer];
    AttributeMap::iterator it = m.find(name);

    if ( it != m.end() ) {
        Attribute& a = it->second;
        return a.GetValue(dflt);
    }
    return dflt;
}

double Cake::GetReal (const char* s, double dflt) {
    string name(s);
    AttributeMap& m = my->attribs[my->layer];
    AttributeMap::iterator it = m.find(name);

    if ( it != m.end() ) {
        Attribute& a = it->second;
        return a.GetReal(dflt);
    }
    return dflt;
}

Cake* cake = nullptr;

