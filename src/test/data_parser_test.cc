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
