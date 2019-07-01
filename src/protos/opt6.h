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
// ip6 extension hop-by-hop and dest options stuff
//-------------------------------------------------------------------------

#ifndef __OPT6_H__
#define __OPT6_H__

#include "protocol.h"

class Opt6Protocol : public Protocol {
public:
    ~Opt6Protocol() override;

    bool Bind(const std::string&) override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;
    const uint8_t* GetOptions(const Packet&, uint32_t&) override;

protected:
    Opt6Protocol(const char*);

private:
    class Opt6Impl* my;
};

class Hop6Protocol : public Opt6Protocol {
public:
    Hop6Protocol() : Opt6Protocol("hop6") { }
    static class Pimp* GetPimp();
};

class Dst6Protocol : public Opt6Protocol {
public:
    Dst6Protocol() : Opt6Protocol("dst6") { }
    static Pimp* GetPimp();
};

#ifdef __PROTOTOOL_TAG__
#include "opt6.h"
PROTOTOOL_NEW(Dst6Protocol);
#endif

#ifdef __PROTOTOOL_TAG__
#include "opt6.h"
PROTOTOOL_NEW(Hop6Protocol);
#endif

#endif

