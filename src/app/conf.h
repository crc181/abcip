//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2026 Charles R. Combs
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

#ifndef __CONF_H__
#define __CONF_H__

#include <cstdint>
#include <iosfwd>

class Conf {
public:
    Conf(int argc, char* argv[], std::ostream& out = get_cout());

public:
    const char* pcap;
    const char* stack;
    const char* user;
    uint16_t snap;
    bool trace, trace_parser, raw, done;

private:
    static std::ostream& get_cout();
};

#endif
