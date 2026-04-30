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

#ifndef __ATTRIBUTE_H__
#define __ATTRIBUTE_H__

#include <cstdint>
#include <string>

class Attribute {
public:
    Attribute(bool b = false) { sticky = b; }
    virtual ~Attribute() = default;

    void Clear() { value.clear(); }
    void Reset() { if ( !sticky ) value.clear(); }
    bool IsSet() { return !value.empty(); }

    void Set(const std::string& v) { Compress(v); }
    void Set(const char* v) { value = v; }

    void Print(std::ostream& out) { Expand(out); }
    const std::string& GetValue() { return value; }

    int32_t GetValue(int32_t dflt);
    uint32_t GetValue(uint32_t dflt);
    double GetReal(double dflt);

    bool IsSticky() { return sticky; }
    void SetSticky(bool b) { sticky = b; }

protected:
    bool Compress(const std::string&);
    void Expand(std::ostream& out);

private:
    std::string value;
    bool sticky;
};

#endif

