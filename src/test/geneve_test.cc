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
#include "cake.h"
#include "geneve.h"
#include "packet.h"

#include <arpa/inet.h>

// GeneveHdr layout (matches geneve.cc internal struct)
struct GeneveHdr {
    uint8_t  g_vol;
    uint8_t  g_flags;
    uint16_t g_proto;
    uint8_t  g_vni[3];
    uint8_t  g_rsvd2;
};

static const uint8_t GENEVE_FLAG_O = 0x80;
static const uint8_t GENEVE_FLAG_C = 0x40;

// -------------------------------------------------------------------------
// Bind
// -------------------------------------------------------------------------

TEST_CASE("GeneveProtocol::Bind accepts eth/ip4/ip6/arp", "[geneve]") {
    GeneveProtocol g;
    CHECK(g.Bind("eth"));
    CHECK(g.Bind("ip4"));
    CHECK(g.Bind("ip6"));
    CHECK(g.Bind("arp"));
}

TEST_CASE("GeneveProtocol::Bind rejects unknown protocol", "[geneve]") {
    GeneveProtocol g;
    CHECK_FALSE(g.Bind("tcp"));
    CHECK_FALSE(g.Bind("udp"));
    CHECK_FALSE(g.Bind("xyz"));
}

// -------------------------------------------------------------------------
// VNI encoding
// -------------------------------------------------------------------------

TEST_CASE("Geneve VNI is encoded as 24-bit big-endian", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);

    cake.Store("vni", "0x123456");
    g.Fetch(cake, true);

    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK(h->g_vni[0] == 0x12);
    CHECK(h->g_vni[1] == 0x34);
    CHECK(h->g_vni[2] == 0x56);
}

TEST_CASE("Geneve VNI zero by default", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK(h->g_vni[0] == 0);
    CHECK(h->g_vni[1] == 0);
    CHECK(h->g_vni[2] == 0);
}

// -------------------------------------------------------------------------
// Version field
// -------------------------------------------------------------------------

TEST_CASE("Geneve version field default is 0", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK((h->g_vol >> 6) == 0);
}

TEST_CASE("Geneve version field can be set via cake", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    cake.Store("ver", "1");
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK((h->g_vol >> 6) == 1);
}

// -------------------------------------------------------------------------
// Flags
// -------------------------------------------------------------------------

TEST_CASE("Geneve C flag set via Fetch", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    cake.Store("c", "1");
    g.Fetch(cake, true);
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK(h->g_flags & GENEVE_FLAG_C);
}

TEST_CASE("Geneve O flag set via Fetch", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    cake.Store("o", "1");
    g.Fetch(cake, true);
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK(h->g_flags & GENEVE_FLAG_O);
}

TEST_CASE("Geneve O flag cleared via GetHeader when cake sets o=0", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);

    // set via Fetch
    cake.Store("o", "1");
    g.Fetch(cake, true);

    // override to clear via GetHeader
    cake.Store("o", "0");
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK_FALSE(h->g_flags & GENEVE_FLAG_O);
}

// -------------------------------------------------------------------------
// Header size
// -------------------------------------------------------------------------

TEST_CASE("Geneve header is 8 bytes with no options", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t hlen = 0;
    g.GetHeader(pkt, hlen);
    CHECK(hlen == 8u);
}

// -------------------------------------------------------------------------
// Options
// -------------------------------------------------------------------------

TEST_CASE("Geneve GetOptions returns empty when none set", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t olen = 0;
    const uint8_t* opts = g.GetOptions(pkt, olen);
    CHECK(olen == 0u);
    CHECK(opts == nullptr);
}

TEST_CASE("Geneve GetOptions returns data when opt is set", "[geneve]") {
    GeneveProtocol g;
    Cake cake(2);
    Packet pkt(cake);
    cake.Store("opt", "|01020304|");
    g.Fetch(cake, true);
    uint32_t olen = 0;
    const uint8_t* opts = g.GetOptions(pkt, olen);
    REQUIRE(opts != nullptr);
    CHECK(olen == 4u);
    CHECK(opts[0] == 0x01);
    CHECK(opts[3] == 0x04);
}

// -------------------------------------------------------------------------
// Proto binding reflected in header
// -------------------------------------------------------------------------

TEST_CASE("Geneve proto is set to eth tunnel type after Bind(eth)", "[geneve]") {
    GeneveProtocol g;
    g.Bind("eth");
    Cake cake(2);
    Packet pkt(cake);
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->g_proto) == 0x6558u);
}

TEST_CASE("Geneve proto is set to IPv4 after Bind(ip4)", "[geneve]") {
    GeneveProtocol g;
    g.Bind("ip4");
    Cake cake(2);
    Packet pkt(cake);
    uint32_t hlen = 0;
    const GeneveHdr* h = reinterpret_cast<const GeneveHdr*>(g.GetHeader(pkt, hlen));
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->g_proto) == 0x0800u);
}
