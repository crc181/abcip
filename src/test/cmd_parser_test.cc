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

#include "cmd_parser.h"
#include "command.h"
#include "status.h"
#include "stream_reader.h"

struct StatusGuard {
    StatusGuard() { status = Status(); }
};

struct SuppressCerr {
    SuppressCerr() : old(std::cerr.rdbuf(ss.rdbuf())) { }
    ~SuppressCerr() { std::cerr.rdbuf(old); }
    std::ostringstream ss;
    std::streambuf* old;
};

static CommandParser* make_parser(const std::string& text, const char* cmds = "abcd")
{
    auto* ss = new std::istringstream(text);
    *ss >> std::noskipws;
    auto* r = new StreamReader(ss);
    return new CommandParser(r, cmds);
}

// -------------------------------------------------------------------------
// Basic load
// -------------------------------------------------------------------------

TEST_CASE("CommandParser empty input returns false", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK(p->Good());
    delete p;
}

TEST_CASE("CommandParser simple command a()", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a()");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetName() == "a");
    CHECK(cmd.GetOption(0) == nullptr);
    CHECK(p->Good());
    delete p;
}

TEST_CASE("CommandParser command with key=value option", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a(syn=1)");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetName() == "a");
    Option* o = cmd.GetOption(0);
    REQUIRE(o != nullptr);
    CHECK(o->key == "syn");
    CHECK(o->value == "1");
    delete p;
}

TEST_CASE("CommandParser command with bare key (null value)", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a(syn)");
    Command cmd;
    CHECK(p->Load(cmd));
    Option* o = cmd.GetOption(0);
    REQUIRE(o != nullptr);
    CHECK(o->key == "syn");
    CHECK(o->value == " ");
    delete p;
}

TEST_CASE("CommandParser command with context", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("sess:a(syn=1)");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetContext() == "sess");
    CHECK(cmd.GetName() == "a");
    delete p;
}

TEST_CASE("CommandParser multiple options comma-separated", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a(syn=1,ack=2)");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetOption(0) != nullptr);
    CHECK(cmd.GetOption(1) != nullptr);
    CHECK(cmd.GetOption(0)->key == "syn");
    CHECK(cmd.GetOption(1)->key == "ack");
    delete p;
}

TEST_CASE("CommandParser option with proto prefix", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("c(ip4:a=\"1.2.3.4\")");
    Command cmd;
    CHECK(p->Load(cmd));
    Option* o = cmd.GetOption(0);
    REQUIRE(o != nullptr);
    CHECK(o->proto == "ip4");
    CHECK(o->key == "a");
    delete p;
}

TEST_CASE("CommandParser layer index prefix", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a(1:syn=1)");
    Command cmd;
    CHECK(p->Load(cmd));
    Option* o = cmd.GetOption(0);
    REQUIRE(o != nullptr);
    CHECK(o->index == 1);
    CHECK(o->key == "syn");
    delete p;
}

TEST_CASE("CommandParser negative layer index", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a(-1:syn=1)");
    Command cmd;
    CHECK(p->Load(cmd));
    Option* o = cmd.GetOption(0);
    REQUIRE(o != nullptr);
    CHECK((int)o->index == -1);
    delete p;
}

TEST_CASE("CommandParser semicolon separator resets index and proto", "[cmd_parser]") {
    StatusGuard sg;
    // semicolon in state 7 (bare key before =) and state 9 (after value)
    CommandParser* p = make_parser("a(syn;ack=2)");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetOption(0) != nullptr);
    CHECK(cmd.GetOption(1) != nullptr);
    CHECK(cmd.GetOption(0)->key == "syn");
    CHECK(cmd.GetOption(1)->key == "ack");
    delete p;
}

TEST_CASE("CommandParser semicolon after value", "[cmd_parser]") {
    StatusGuard sg;
    // semicolon in state 9
    CommandParser* p = make_parser("a(syn=1;ack=2)");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetOption(0)->key == "syn");
    CHECK(cmd.GetOption(1)->key == "ack");
    delete p;
}

TEST_CASE("CommandParser string value with escape", "[cmd_parser]") {
    StatusGuard sg;
    // exercises state 6 (backslash escape inside string)
    CommandParser* p = make_parser("a(key=\"val\\\"ue\")");
    Command cmd;
    CHECK(p->Load(cmd));
    Option* o = cmd.GetOption(0);
    REQUIRE(o != nullptr);
    CHECK(o->key == "key");
    delete p;
}

TEST_CASE("CommandParser adjacent string tokens (state 4 re-open quote)", "[cmd_parser]") {
    StatusGuard sg;
    // state 4: second '"' re-enters string state
    CommandParser* p = make_parser("a(key=\"foo\"\"bar\")");
    Command cmd;
    CHECK(p->Load(cmd));
    delete p;
}

TEST_CASE("CommandParser comment after closing quote (state 5)", "[cmd_parser]") {
    StatusGuard sg;
    // state 4 -> state 5: '#' after closing quote treated as comment
    CommandParser* p = make_parser("a(key=\"foo\"#comment\n)");
    Command cmd;
    CHECK(p->Load(cmd));
    Option* o = cmd.GetOption(0);
    REQUIRE(o != nullptr);
    CHECK(o->key == "key");
    delete p;
}

TEST_CASE("CommandParser comment line", "[cmd_parser]") {
    StatusGuard sg;
    // state 1: '#' starts comment
    CommandParser* p = make_parser("# comment\na(syn=1)");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetName() == "a");
    delete p;
}

TEST_CASE("CommandParser GetLocation returns line and pos", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a(syn=1)");
    int y = -1, x = -1;
    p->GetLocation(y, x);
    CHECK(y >= 0);
    CHECK(x >= 0);
    delete p;
}

// -------------------------------------------------------------------------
// Punctuation token when tok already started (Lexer state 0 lines 107-108)
// -------------------------------------------------------------------------

TEST_CASE("CommandParser punctuation terminates word token", "[cmd_parser]") {
    StatusGuard sg;
    // 'a(' — 'a' is a word token, then '(' is punctuation that terminates it
    // exercises the !tok.empty() path (lines 107-108)
    CommandParser* p = make_parser("a(syn=1)");
    Command cmd;
    CHECK(p->Load(cmd));
    delete p;
}

// -------------------------------------------------------------------------
// Error paths
// -------------------------------------------------------------------------

TEST_CASE("CommandParser bad first token returns false and sets bad", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // '(' at start is punctuation, not alpha/digit → "expected alpha or digit"
    CommandParser* p = make_parser("(bad)");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser unknown command returns false", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    CommandParser* p = make_parser("z()", "abcd");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser unexpected token after command name", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 1: token after command name is not '(' or ':' → "expected ':' or '('"
    CommandParser* p = make_parser("a=bad");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser unknown command after context", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 2: command name after context not in commands → "unknown command"
    CommandParser* p = make_parser("sess:z()");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser missing paren after context:cmd", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 3: expected '(' after "ctx:cmd" → "expected '('"
    CommandParser* p = make_parser("sess:a syn=1)");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser missing colon after layer index", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 5: digit found but next is not ':' → "expected ':'"
    CommandParser* p = make_parser("a(1 syn=1)");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser non-alpha after proto colon (state 11)", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 11: after "proto:" expects alpha var name
    CommandParser* p = make_parser("a(ip4:1=bad)");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser non-alpha var in state 4", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 4/6: not digit and not alpha and not ')' → "expected var"
    CommandParser* p = make_parser("a(=bad)");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser bad token after key (state 7)", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 7: after key, unexpected token (not =, comma, ), ;)
    CommandParser* p = make_parser("a(syn bad)");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser bad token after value (state 9)", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // state 9: after value, unexpected token
    CommandParser* p = make_parser("a(syn=1 bad)");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser incomplete command sets bad", "[cmd_parser]") {
    StatusGuard sg;
    SuppressCerr sc;
    // space forces 'a' token to be returned, then EOF in state 1 → "incomplete command"
    CommandParser* p = make_parser("a ");
    Command cmd;
    CHECK_FALSE(p->Load(cmd));
    CHECK_FALSE(p->Good());
    delete p;
}

TEST_CASE("CommandParser multiple commands", "[cmd_parser]") {
    StatusGuard sg;
    CommandParser* p = make_parser("a(syn=1)\nb(ack=2)");
    Command cmd;
    CHECK(p->Load(cmd));
    CHECK(cmd.GetName() == "a");
    cmd.Clear();
    CHECK(p->Load(cmd));
    CHECK(cmd.GetName() == "b");
    CHECK_FALSE(p->Load(cmd));
    delete p;
}
