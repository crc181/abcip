#include <catch2/catch_all.hpp>
#include "cake.h"

// -------------------------------------------------------------------------
// Layer navigation
// -------------------------------------------------------------------------

TEST_CASE("Cake default layer is 1", "[cake]") {
    Cake c(4);
    CHECK(c.GetLayer() == 1u);
}

TEST_CASE("Cake::Next advances layer", "[cake]") {
    Cake c(4);
    CHECK(c.Next());
    CHECK(c.GetLayer() == 2u);
}

TEST_CASE("Cake::Next returns false at max layer", "[cake]") {
    Cake c(2);
    c.Next();
    CHECK_FALSE(c.Next());
    CHECK(c.GetLayer() == 2u);
}

TEST_CASE("Cake::Prev returns false at min layer", "[cake]") {
    Cake c(4);
    CHECK_FALSE(c.Prev());
    CHECK(c.GetLayer() == 1u);
}

TEST_CASE("Cake::SetLastLayer sets to max", "[cake]") {
    Cake c(4);
    c.SetLastLayer();
    CHECK(c.GetLayer() == 4u);
}

TEST_CASE("Cake::SetFirstLayer resets to 1", "[cake]") {
    Cake c(4);
    c.SetLastLayer();
    c.SetFirstLayer();
    CHECK(c.GetLayer() == 1u);
}

TEST_CASE("Cake::SetLayer accepts valid layers", "[cake]") {
    Cake c(4);
    CHECK(c.SetLayer(3));
    CHECK(c.GetLayer() == 3u);
}

TEST_CASE("Cake::SetLayer rejects out-of-range", "[cake]") {
    Cake c(4);
    CHECK_FALSE(c.SetLayer(5));
}

TEST_CASE("Cake::SetLayer(0) aliases to max layer", "[cake]") {
    Cake c(4);
    CHECK(c.SetLayer(0));
    CHECK(c.GetLayer() == 4u);
}

TEST_CASE("Cake::GetTopLayer returns max", "[cake]") {
    Cake c(7);
    CHECK(c.GetTopLayer() == 7u);
}

// -------------------------------------------------------------------------
// Store / IsSet / GetValue / GetReal
// -------------------------------------------------------------------------

TEST_CASE("Cake::Store and IsSet on same layer", "[cake]") {
    Cake c(4);
    c.Store("key", "val");
    CHECK(c.IsSet("key"));
}

TEST_CASE("Cake::IsSet returns false on different layer", "[cake]") {
    Cake c(4);
    c.Store("key", "val");
    c.Next();
    CHECK_FALSE(c.IsSet("key"));
}

TEST_CASE("Cake::GetValue(uint32) returns stored integer", "[cake]") {
    Cake c(4);
    c.Store("num", "42");
    CHECK(c.GetValue("num", 0u) == 42u);
}

TEST_CASE("Cake::GetValue(uint32) returns default for missing key", "[cake]") {
    Cake c(4);
    CHECK(c.GetValue("missing", 99u) == 99u);
}

TEST_CASE("Cake::GetReal returns stored double", "[cake]") {
    Cake c(4);
    c.Store("r", "1.5");
    CHECK(c.GetReal("r", 0.0) == Catch::Approx(1.5));
}

TEST_CASE("Cake::GetValue(string) returns stored string", "[cake]") {
    Cake c(4);
    c.Store("s", "hello");
    CHECK(c.GetValue("s") == "hello");
}

TEST_CASE("Cake::GetValue returns empty string for missing key", "[cake]") {
    Cake c(4);
    CHECK(c.GetValue("no").empty());
}

// -------------------------------------------------------------------------
// Reset / Clear / Sticky
// -------------------------------------------------------------------------

TEST_CASE("Cake::Reset clears non-sticky attributes on all layers", "[cake]") {
    Cake c(2);
    c.Store("a", "1");
    c.Next();
    c.Store("b", "2");
    c.Reset();
    c.SetFirstLayer();
    CHECK_FALSE(c.IsSet("a"));
    c.Next();
    CHECK_FALSE(c.IsSet("b"));
}

TEST_CASE("Cake::Reset preserves sticky attributes", "[cake]") {
    Cake c(2);
    // Store on layer 1; Reset moves layer to max (2), so go back to check
    c.Store("s", "sticky", true);
    c.Reset();
    c.SetFirstLayer();
    CHECK(c.IsSet("s"));
}

TEST_CASE("Cake::Reset(key) clears single key on current layer", "[cake]") {
    Cake c(4);
    c.Store("a", "1");
    c.Store("b", "2");
    c.Reset("a");
    CHECK_FALSE(c.IsSet("a"));
    CHECK(c.IsSet("b"));
}

TEST_CASE("Cake::Clear removes attribute regardless of sticky", "[cake]") {
    Cake c(4);
    c.Store("s", "val", true);
    c.Clear("s");
    CHECK_FALSE(c.IsSet("s"));
}

TEST_CASE("Cake::EmptyLayer is true before any stores", "[cake]") {
    Cake c(4);
    CHECK(c.EmptyLayer());
}

TEST_CASE("Cake::EmptyLayer is false after Store", "[cake]") {
    Cake c(4);
    c.Store("x", "1");
    CHECK_FALSE(c.EmptyLayer());
}

// -------------------------------------------------------------------------
// Restart
// -------------------------------------------------------------------------

TEST_CASE("Cake::Restart resets layers and clears attributes", "[cake]") {
    Cake c(4);
    c.Store("x", "1");
    c.Restart(2);
    CHECK(c.GetTopLayer() == 2u);
    CHECK(c.GetLayer() == 1u);
    CHECK_FALSE(c.IsSet("x"));
}
