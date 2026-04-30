#include <catch2/catch_all.hpp>
#include "attribute.h"

#include <sstream>

// -------------------------------------------------------------------------
// GetValue / GetReal
// -------------------------------------------------------------------------

TEST_CASE("Attribute::GetValue(uint32_t) parses decimals and hex", "[attribute]") {
    Attribute a;
    a.Set("42");
    CHECK(a.GetValue(0u) == 42u);

    a.Set("0xff");
    CHECK(a.GetValue(0u) == 255u);

    a.Set("0");
    CHECK(a.GetValue(99u) == 0u);
}

TEST_CASE("Attribute::GetValue(uint32_t) returns default on bad input", "[attribute]") {
    Attribute a;
    CHECK(a.GetValue(7u) == 7u);   // empty

    a.Set("abc");
    CHECK(a.GetValue(7u) == 7u);   // non-numeric

    a.Set("12x");
    CHECK(a.GetValue(7u) == 7u);   // trailing garbage
}

TEST_CASE("Attribute::GetValue(int32_t) handles negatives", "[attribute]") {
    Attribute a;
    a.Set("-1");
    CHECK(a.GetValue(int32_t(0)) == -1);
}

TEST_CASE("Attribute::GetReal parses doubles", "[attribute]") {
    Attribute a;
    a.Set("3.14");
    CHECK(a.GetReal(0.0) == Catch::Approx(3.14));

    a.Set("0.0");
    CHECK(a.GetReal(1.0) == Catch::Approx(0.0));
}

TEST_CASE("Attribute::GetReal returns default on bad input", "[attribute]") {
    Attribute a;
    CHECK(a.GetReal(2.5) == Catch::Approx(2.5));   // empty

    a.Set("xyz");
    CHECK(a.GetReal(2.5) == Catch::Approx(2.5));
}

// -------------------------------------------------------------------------
// Compress / Expand round-trip
// -------------------------------------------------------------------------

TEST_CASE("Attribute::Set plain string stores verbatim", "[attribute]") {
    Attribute a;
    a.Set(std::string("hello"));
    CHECK(a.GetValue() == "hello");
}

TEST_CASE("Attribute::Set with pipe-hex embeds binary bytes", "[attribute]") {
    Attribute a;
    a.Set(std::string("|41 42 43|"));   // 'A' 'B' 'C'
    CHECK(a.GetValue() == "ABC");
}

TEST_CASE("Attribute::Set with mixed text and hex", "[attribute]") {
    Attribute a;
    a.Set(std::string("x|0d0a|y"));     // x CR LF y
    std::string expected = "x\r\ny";
    CHECK(a.GetValue() == expected);
}

TEST_CASE("Attribute::Set strips surrounding quotes", "[attribute]") {
    Attribute a;
    a.Set(std::string("\"hello\""));
    CHECK(a.GetValue() == "hello");
}

TEST_CASE("Attribute::Set handles backslash escape", "[attribute]") {
    Attribute a;
    a.Set(std::string("a\\|b"));   // literal |
    CHECK(a.GetValue() == "a|b");
}

TEST_CASE("Attribute::Print round-trips printable strings", "[attribute]") {
    Attribute a;
    a.Set(std::string("hello"));
    std::ostringstream oss;
    a.Print(oss);
    CHECK(oss.str() == "\"hello\"");
}

TEST_CASE("Attribute::Print encodes non-printable bytes in hex", "[attribute]") {
    Attribute a;
    a.Set(std::string("|0d0a|"));
    std::ostringstream oss;
    a.Print(oss);
    // should contain pipe-delimited hex for CR and LF
    std::string out = oss.str();
    CHECK(out.find('|') != std::string::npos);
}

// -------------------------------------------------------------------------
// Sticky / Reset / Clear / IsSet
// -------------------------------------------------------------------------

TEST_CASE("Attribute sticky flag survives Reset", "[attribute]") {
    Attribute a(true);
    a.Set(std::string("val"));
    a.Reset();
    CHECK(a.IsSet());
    CHECK(a.GetValue() == "val");
}

TEST_CASE("Attribute non-sticky cleared by Reset", "[attribute]") {
    Attribute a(false);
    a.Set(std::string("val"));
    a.Reset();
    CHECK_FALSE(a.IsSet());
}

TEST_CASE("Attribute::Clear always clears regardless of sticky", "[attribute]") {
    Attribute a(true);
    a.Set(std::string("val"));
    a.Clear();
    CHECK_FALSE(a.IsSet());
}

TEST_CASE("Attribute::SetSticky can be toggled", "[attribute]") {
    Attribute a(true);
    a.Set(std::string("val"));
    a.SetSticky(false);
    CHECK_FALSE(a.IsSticky());
    a.Reset();
    CHECK_FALSE(a.IsSet());
}
