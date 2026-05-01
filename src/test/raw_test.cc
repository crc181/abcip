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
