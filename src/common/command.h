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
// command stuff
//-------------------------------------------------------------------------

#ifndef __COMMAND_H__
#define __COMMAND_H__

#include <string>
#include <vector>

class Option {
public:
    Option(unsigned u, const std::string& k,
        const std::string& v, const std::string& p) :
        index(u), key(k), value(v), proto(p) { }
    void SetPos(unsigned r, unsigned c)
        { row = r; col = c; }

public:
    unsigned index;
    std::string key;
    std::string value;
    std::string proto;
    unsigned row = 0;
    unsigned col = 0;
};

typedef std::vector<Option*> OptVector;

class Command {
public:
    Command() = default;
    virtual ~Command() = default;

    void SetName(std::string& s) { name = s; }
    std::string& GetName() { return name; }

    void SetContext(std::string& s) { context = s; }
    std::string& GetContext() { return context; }

    void AddOption(Option* o) {
        opts.push_back(o);
    }
    Option* GetOption(unsigned at) {
        return at < opts.size() ? opts[at] : nullptr;
    }
    Option* operator[](unsigned at) {
        return at < opts.size() ? opts[at] : nullptr;
    }
    void Clear() {
        for ( OptVector::iterator it = opts.begin(); it != opts.end(); ++it )
            delete *it;
        opts.clear();
        context.clear();
        name.clear();
    }
private:
    std::string name;
    std::string context;
    OptVector opts;
};

#endif

