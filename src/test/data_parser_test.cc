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
#include <string>

#include "command.h"
#include "data_parser.h"
#include "reader.h"

class StringReader : public Reader {
public:
    StringReader(const std::string& s) : buf(s), pos(0) { }
    bool operator>>(char& c) override {
        if (pos >= buf.size()) return false;
        c = buf[pos++];
        return true;
    }
private:
    std::string buf;
    size_t pos;
};

TEST_CASE("DataParser::Load returns false on empty input", "[data_parser]") {
    DataParser dp(new StringReader(""), "a", "pay");
    Command cmd;
    CHECK_FALSE(dp.Load(cmd));
}

TEST_CASE("DataParser::Load returns true for a line of data", "[data_parser]") {
    DataParser dp(new StringReader("hello\n"), "a", "pay");
    Command cmd;
    REQUIRE(dp.Load(cmd));
}

TEST_CASE("DataParser::Load sets command name", "[data_parser]") {
    DataParser dp(new StringReader("hello\n"), "a", "pay");
    Command cmd;
    dp.Load(cmd);
    CHECK(cmd.GetName() == "a");
}

TEST_CASE("DataParser::Load wraps value in quotes", "[data_parser]") {
    DataParser dp(new StringReader("hello\n"), "a", "pay");
    Command cmd;
    dp.Load(cmd);
    Option* opt = cmd.GetOption(0);
    REQUIRE(opt != nullptr);
    CHECK(opt->value == "\"hello\"");
    CHECK(opt->key == "pay");
}

TEST_CASE("DataParser::Load adds ack option", "[data_parser]") {
    DataParser dp(new StringReader("hello\n"), "a", "pay");
    Command cmd;
    dp.Load(cmd);
    Option* ack = cmd.GetOption(1);
    REQUIRE(ack != nullptr);
    CHECK(ack->key == "ack");
    CHECK(ack->value == "1");
}

TEST_CASE("DataParser::Load returns false after EOF", "[data_parser]") {
    DataParser dp(new StringReader("hello\n"), "a", "pay");
    Command cmd;
    dp.Load(cmd);
    cmd.Clear();
    CHECK_FALSE(dp.Load(cmd));
}

TEST_CASE("DataParser::GetLocation tracks line number", "[data_parser]") {
    DataParser dp(new StringReader("hello\n"), "a", "pay");
    Command cmd;
    dp.Load(cmd);
    int y = 0, x = 0;
    dp.GetLocation(y, x);
    CHECK(y == 1);
}

TEST_CASE("DataParser::Good is true after successful load", "[data_parser]") {
    DataParser dp(new StringReader("hello\n"), "a", "pay");
    Command cmd;
    dp.Load(cmd);
    CHECK(dp.Good());
}
