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

#include "field.h"
#include "status.h"

struct StatusGuard {
    StatusGuard() { status = Status(); }
};

struct SuppressCerr {
    SuppressCerr() : old(std::cerr.rdbuf(ss.rdbuf())) { }
    ~SuppressCerr() { std::cerr.rdbuf(old); }
    std::ostringstream ss;
    std::streambuf* old;
};

// One field per type under test, terminated by null name sentinel
static const Field s_fields[] = {
    { FT_PKT, "str",   "s*",     "string field" },
    { FT_PKT, "ip4",   "a4",     "ipv4 address" },
    { FT_PKT, "ip6",   "a16",    "ipv6 address" },
    { FT_PKT, "mac",   "a6",     "mac address"  },
    { FT_PKT, "flag",  "b",      "bool flag"    },
    { FT_PKT, "u8v",   "u8",     "uint8"        },
    { FT_PKT, "u32m",  "u32|max","uint32 or max"},
    { FT_PKT, "i32v",  "i32",    "int32"        },
    { FT_PKT, "r32v",  "r32",    "float32"      },
    { FT_CFG, "cstr",  "s*",     "cfg string"   },
    { FT_DEF, "dstr",  "s*",     "def string"   },
    { FT_PKT, "unk",   "x99",    "unknown type" },
    { FT_MAX, nullptr, nullptr,  nullptr        },
};

static bool v(const char* key, const char* val, FieldType ft = FT_PKT) {
    return Field::Validate(s_fields, ft, key, val);
}

// -------------------------------------------------------------------------
// GetType
// -------------------------------------------------------------------------

TEST_CASE("Field::GetType a and b return FT_PKT", "[field]") {
    CHECK(Field::GetType("a") == FT_PKT);
    CHECK(Field::GetType("b") == FT_PKT);
}

TEST_CASE("Field::GetType c returns FT_CFG", "[field]") {
    CHECK(Field::GetType("c") == FT_CFG);
}

TEST_CASE("Field::GetType d returns FT_DEF", "[field]") {
    CHECK(Field::GetType("d") == FT_DEF);
}

TEST_CASE("Field::GetType unknown returns FT_MAX", "[field]") {
    CHECK(Field::GetType("z") == FT_MAX);
    CHECK(Field::GetType("") == FT_MAX);
}

// -------------------------------------------------------------------------
// Print
// -------------------------------------------------------------------------

TEST_CASE("Field::Print outputs matching fields", "[field]") {
    std::ostringstream out;
    std::string type = "test";
    Field::Print(out, FT_PKT, type, s_fields);
    CHECK(out.str().find("str") != std::string::npos);
    CHECK(out.str().find("ip4") != std::string::npos);
}

TEST_CASE("Field::Print skips non-matching FieldType", "[field]") {
    std::ostringstream out;
    std::string type = "test";
    Field::Print(out, FT_DEF, type, s_fields);
    // only FT_DEF field "dstr" should appear, not "ip4"
    CHECK(out.str().find("dstr") != std::string::npos);
    CHECK(out.str().find("ip4") == std::string::npos);
}

// -------------------------------------------------------------------------
// operator<<
// -------------------------------------------------------------------------

TEST_CASE("Field operator<< formats name type help", "[field]") {
    std::ostringstream out;
    out << s_fields[0];
    CHECK(out.str().find("str") != std::string::npos);
    CHECK(out.str().find("s*") != std::string::npos);
}

// -------------------------------------------------------------------------
// Validate: s* (string)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate s* valid quoted string", "[field]") {
    StatusGuard sg;
    CHECK(v("str", "\"hello\""));
}

TEST_CASE("Field::Validate s* unquoted string fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("str", "hello"));
}

TEST_CASE("Field::Validate s* empty quoted string fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    // quoted but content is empty after stripping: val is "\"\""
    CHECK_FALSE(v("str", "\"\""));
}

// -------------------------------------------------------------------------
// Validate: a4 (IPv4 address)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate a4 valid address", "[field]") {
    StatusGuard sg;
    CHECK(v("ip4", "\"1.2.3.4\""));
}

TEST_CASE("Field::Validate a4 bad address fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("ip4", "\"999.999.999.999\""));
}

// -------------------------------------------------------------------------
// Validate: a16 (IPv6 address)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate a16 valid address", "[field]") {
    StatusGuard sg;
    CHECK(v("ip6", "\"::1\""));
}

TEST_CASE("Field::Validate a16 bad address fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("ip6", "\"not-an-ipv6\""));
}

// -------------------------------------------------------------------------
// Validate: a6 (MAC address)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate a6 valid MAC", "[field]") {
    StatusGuard sg;
    CHECK(v("mac", "\"00:11:22:33:44:55\""));
}

TEST_CASE("Field::Validate a6 bad MAC fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("mac", "\"not-a-mac\""));
}

// -------------------------------------------------------------------------
// Validate: b (bool)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate b accepts any value", "[field]") {
    StatusGuard sg;
    CHECK(v("flag", " "));
    CHECK(v("flag", "1"));
}

// -------------------------------------------------------------------------
// Validate: u* (unsigned int)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate u8 valid value", "[field]") {
    StatusGuard sg;
    CHECK(v("u8v", "255"));
}

TEST_CASE("Field::Validate u8 flag (space) valid", "[field]") {
    StatusGuard sg;
    CHECK(v("u8v", " "));
}

TEST_CASE("Field::Validate u8 out of range fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("u8v", "256"));
}

TEST_CASE("Field::Validate u8 non-number fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("u8v", "abc"));
}

TEST_CASE("Field::Validate u32|max accepts max", "[field]") {
    StatusGuard sg;
    CHECK(v("u32m", "max"));
}

TEST_CASE("Field::Validate u32|max accepts number", "[field]") {
    StatusGuard sg;
    CHECK(v("u32m", "100"));
}

// -------------------------------------------------------------------------
// Validate: i* (signed int)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate i32 valid value", "[field]") {
    StatusGuard sg;
    CHECK(v("i32v", "42"));
}

TEST_CASE("Field::Validate i32 non-number fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("i32v", "xyz"));
}

// -------------------------------------------------------------------------
// Validate: r* (float)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate r32 valid float", "[field]") {
    StatusGuard sg;
    CHECK(v("r32v", "3.14"));
}

TEST_CASE("Field::Validate r32 non-number fails", "[field]") {
    StatusGuard sg;
    SuppressCerr sc;
    CHECK_FALSE(v("r32v", "abc"));
}

// -------------------------------------------------------------------------
// Validate: unknown key / unknown type
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate unknown key returns false", "[field]") {
    StatusGuard sg;
    CHECK_FALSE(v("nosuchkey", "1"));
}

TEST_CASE("Field::Validate unknown type returns false", "[field]") {
    StatusGuard sg;
    CHECK_FALSE(v("unk", "1"));
}

TEST_CASE("Field::Validate null/empty guard", "[field]") {
    StatusGuard sg;
    // empty value triggers the null/empty guard at line 162
    CHECK_FALSE(v("str", ""));
}

// -------------------------------------------------------------------------
// Validate: field type mismatch (FT_CFG key looked up as FT_PKT)
// -------------------------------------------------------------------------

TEST_CASE("Field::Validate wrong FieldType returns false", "[field]") {
    StatusGuard sg;
    // "cstr" is FT_CFG, not FT_PKT
    CHECK_FALSE(v("cstr", "\"hello\"", FT_PKT));
    CHECK(v("cstr", "\"hello\"", FT_CFG));
}
