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
// cake (common attribute keeper) stuff
//-------------------------------------------------------------------------

#ifndef __CAKE_H__
#define __CAKE_H__

#include <cstdint>
#include <string>

class Cake {
public:
    Cake(unsigned max = 8);
    virtual ~Cake();

    void Restart(unsigned max = 8);

    void Store(const char* key, const char* val = "", bool sticky = false);
    void Dump();

    void Reset();
    void Reset(const char*);
    void Clear(const char*);

    bool IsSet(const char*);
    bool IsSet(std::string&);

    void Set(const char*, const std::string&);
    void Set(const std::string&, const std::string&);

    const char* GetCValue(const char*);
    const std::string& GetValue(const char*);
    uint32_t GetValue(const char*, uint32_t dflt);
    double GetReal(const char*, double dflt);

    void SetFirstLayer();
    void SetLastLayer();

    bool SetLayer(unsigned = 0);
    unsigned GetLayer();
    unsigned GetTopLayer();
    bool EmptyLayer();

    bool Prev();
    bool Next();

private:
    class CakeImpl* my;
};

#endif

