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
#include "ip4.h"
#include "packet.h"

#include <netinet/ip.h>
#include <arpa/inet.h>

// -------------------------------------------------------------------------
// Bind
// -------------------------------------------------------------------------

TEST_CASE("Ip4Protocol::Bind accepts standard protocols", "[ip4]") {
    Ip4Protocol ip;
    CHECK(ip.Bind("tcp"));
    CHECK(ip.Bind("udp"));
    CHECK(ip.Bind("icmp4"));
    CHECK(ip.Bind("gre"));
    CHECK(ip.Bind("raw"));
    CHECK(ip.Bind("ip4"));
    CHECK(ip.Bind("ip6"));
    CHECK(ip.Bind("mpls"));
}

TEST_CASE("Ip4Protocol::Bind rejects unknown protocol", "[ip4]") {
    Ip4Protocol ip;
    CHECK_FALSE(ip.Bind("xyz"));
    CHECK_FALSE(ip.Bind("eth"));
}

// -------------------------------------------------------------------------
// GetHeader field encoding
// -------------------------------------------------------------------------

TEST_CASE("Ip4 header default version is 4", "[ip4]") {
    Ip4Protocol ip;
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    Packet pkt(cake);
    uint32_t len = 0;
    const struct ip* h = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(h->ip_v == 4u);
}

TEST_CASE("Ip4 header default TTL is 64", "[ip4]") {
    Ip4Protocol ip;
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    Packet pkt(cake);
    uint32_t len = 0;
    const struct ip* h = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(h->ip_ttl == 64u);
}

TEST_CASE("Ip4 TTL can be overridden", "[ip4]") {
    Ip4Protocol ip;
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    cake.Store("ttl", "128");
    Packet pkt(cake);
    uint32_t len = 0;
    const struct ip* h = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(h->ip_ttl == 128u);
}

TEST_CASE("Ip4 IP ID starts at 1 and increments each non-fragmented packet", "[ip4]") {
    Ip4Protocol ip;
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");

    Packet pkt1(cake);
    uint32_t len = 0;
    const struct ip* h1 = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt1, len));
    uint16_t id1 = ntohs(h1->ip_id);

    cake.Reset();
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    Packet pkt2(cake);
    const struct ip* h2 = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt2, len));
    uint16_t id2 = ntohs(h2->ip_id);

    CHECK(id2 == id1 + 1);
}

TEST_CASE("Ip4 protocol field reflects Bind", "[ip4]") {
    Ip4Protocol ip;
    ip.Bind("tcp");
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    Packet pkt(cake);
    uint32_t len = 0;
    const struct ip* h = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(h->ip_p == IPPROTO_TCP);
}

TEST_CASE("Ip4 checksum is non-zero", "[ip4]") {
    Ip4Protocol ip;
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    Packet pkt(cake);
    uint32_t len = 0;
    const struct ip* h = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(h->ip_sum != 0);
}

TEST_CASE("Ip4 header length is 20 bytes with no options", "[ip4]") {
    Ip4Protocol ip;
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    Packet pkt(cake);
    uint32_t len = 0;
    ip.GetHeader(pkt, len);
    CHECK(len == 20u);
}

// -------------------------------------------------------------------------
// DF / MF flag encoding
// -------------------------------------------------------------------------

TEST_CASE("Ip4 DF flag is set when cake has df", "[ip4]") {
    Ip4Protocol ip;
    Cake cake(2);
    cake.Store("src", "1.2.3.4");
    cake.Store("dst", "5.6.7.8");
    cake.Store("df", "1");
    Packet pkt(cake);
    uint32_t len = 0;
    const struct ip* h = reinterpret_cast<const struct ip*>(ip.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    uint16_t off = ntohs(h->ip_off);
    CHECK(off & IP_DF);
}
