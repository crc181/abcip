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

#include <catch2/catch_all.hpp>

#include <sstream>

#include "raw.h"
#include "pimp.h"

TEST_CASE("RawProtocol::Bind always returns true", "[raw]") {
    RawProtocol p;
    CHECK(p.Bind("anything"));
    CHECK(p.Bind(""));
}

TEST_CASE("RawProtocol::GetPimp returns non-null", "[raw]") {
    Pimp* pimp = RawProtocol::GetPimp();
    REQUIRE(pimp != nullptr);
    delete pimp;
}

TEST_CASE("RawPimp::New creates a RawProtocol", "[raw]") {
    Pimp* pimp = RawProtocol::GetPimp();
    Protocol* p = pimp->New(nullptr);
    REQUIRE(p != nullptr);
    delete p;
    delete pimp;
}

TEST_CASE("RawPimp::HelpBind produces output containing raw", "[raw]") {
    Pimp* pimp = RawProtocol::GetPimp();
    std::ostringstream out;
    pimp->HelpBind(out);
    CHECK(out.str().find("raw") != std::string::npos);
    delete pimp;
}
