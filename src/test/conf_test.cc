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

#include <iostream>
#include <sstream>

#include "abc_io.h"
#include "conf.h"
#include "data.h"

static Conf make(std::initializer_list<const char*> args, std::ostream& out = std::cout)
{
    std::vector<const char*> v = { "abcip" };
    v.insert(v.end(), args.begin(), args.end());
    return Conf((int)v.size(), (char**)v.data(), out);
}

// -------------------------------------------------------------------------
// Defaults
// -------------------------------------------------------------------------

TEST_CASE("Conf defaults", "[conf]") {
    Conf c = make({});
    CHECK_FALSE(c.done);
    CHECK_FALSE(c.trace);
    CHECK_FALSE(c.raw);
    CHECK(c.pcap == nullptr);
    CHECK(c.snap == 65535);
    CHECK(std::string(c.stack) == DEFAULT_STACK);
    CHECK(std::string(c.user) == DEFAULT_USER);
}

// -------------------------------------------------------------------------
// Flag parsing
// -------------------------------------------------------------------------

TEST_CASE("Conf --pcap sets pcap path", "[conf]") {
    Conf c = make({"--pcap", "/tmp/out.pcap"});
    CHECK_FALSE(c.done);
    CHECK(std::string(c.pcap) == "/tmp/out.pcap");
}

TEST_CASE("Conf --snap sets snaplen", "[conf]") {
    Conf c = make({"--snap", "1518"});
    CHECK_FALSE(c.done);
    CHECK(c.snap == 1518);
}

TEST_CASE("Conf --stack sets stack", "[conf]") {
    Conf c = make({"--stack", "eth:ip6:tcp"});
    CHECK_FALSE(c.done);
    CHECK(std::string(c.stack) == "eth:ip6:tcp");
}

TEST_CASE("Conf --trace sets trace", "[conf]") {
    Conf c = make({"--trace"});
    CHECK_FALSE(c.done);
    CHECK(c.trace);
}

TEST_CASE("Conf --raw sets raw", "[conf]") {
    Conf c = make({"--raw"});
    CHECK_FALSE(c.done);
    CHECK(c.raw);
}

TEST_CASE("Conf --user sets user", "[conf]") {
    Conf c = make({"--user", "dumb"});
    CHECK_FALSE(c.done);
    CHECK(std::string(c.user) == "dumb");
}

TEST_CASE("Conf --full-monty sets data and continues", "[conf]") {
    Conf c = make({"--full-monty"});
    CHECK_FALSE(c.done);
}

TEST_CASE("Conf --full-dubya sets data and continues", "[conf]") {
    Conf c = make({"--full-dubya"});
    CHECK_FALSE(c.done);
}

// -------------------------------------------------------------------------
// Help / info flags set done
// -------------------------------------------------------------------------

TEST_CASE("Conf --help sets done and prints usage", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--help"}, out);
    CHECK(c.done);
    CHECK(out.str().find("abcip") != std::string::npos);
}

TEST_CASE("Conf -? sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"-?"}, out);
    CHECK(c.done);
}

TEST_CASE("Conf --version sets done and prints version", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--version"}, out);
    CHECK(c.done);
    CHECK(out.str().find("abcip") != std::string::npos);
}

TEST_CASE("Conf --license sets done and prints license", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--license"}, out);
    CHECK(c.done);
    CHECK(out.str().find("General Public License") != std::string::npos);
}

TEST_CASE("Conf --help-protos sets done", "[conf]") {
    // HelpTypes writes names to cout (bug) — just verify done is set
    std::ostringstream out;
    std::streambuf* old = std::cout.rdbuf(out.rdbuf());
    Conf c = make({"--help-protos"}, out);
    std::cout.rdbuf(old);
    CHECK(c.done);
    CHECK(out.str().find("ip4") != std::string::npos);
}

TEST_CASE("Conf --help-users sets done and lists users", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--help-users"}, out);
    CHECK(c.done);
    CHECK_FALSE(out.str().empty());
}

TEST_CASE("Conf --help-bind sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--help-bind"}, out);
    CHECK(c.done);
    CHECK_FALSE(out.str().empty());
}

TEST_CASE("Conf --help-packet sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--help-packet"}, out);
    CHECK(c.done);
    CHECK_FALSE(out.str().empty());
}

TEST_CASE("Conf -?a sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"-?a"}, out);
    CHECK(c.done);
}

TEST_CASE("Conf --help-config sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--help-config"}, out);
    CHECK(c.done);
    CHECK_FALSE(out.str().empty());
}

TEST_CASE("Conf -?c sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"-?c"}, out);
    CHECK(c.done);
}

TEST_CASE("Conf --help-define sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--help-define"}, out);
    CHECK(c.done);
    CHECK_FALSE(out.str().empty());
}

TEST_CASE("Conf -?d sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"-?d"}, out);
    CHECK(c.done);
}

TEST_CASE("Conf --help-data sets done and prints data", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--help-data"}, out);
    CHECK(c.done);
    CHECK_FALSE(out.str().empty());
}

// -------------------------------------------------------------------------
// Unknown option
// -------------------------------------------------------------------------

TEST_CASE("Conf unknown option sets done", "[conf]") {
    std::ostringstream out;
    Conf c = make({"--no-such-option"}, out);
    CHECK(c.done);
    CHECK(out.str().find("Unknown") != std::string::npos);
}
