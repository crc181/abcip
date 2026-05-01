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
#include "packet.h"
#include "phy.h"

#include <arpa/inet.h>
#include <sys/socket.h>

// -------------------------------------------------------------------------
// Bind
// -------------------------------------------------------------------------

TEST_CASE("PhyProtocol::Bind always returns true", "[phy]") {
    PhyProtocol p;
    CHECK(p.Bind("eth"));
    CHECK(p.Bind("ip4"));
    CHECK(p.Bind("anything"));
}

// -------------------------------------------------------------------------
// tenant_id propagation
// -------------------------------------------------------------------------

TEST_CASE("Phy tenant_id default is 0", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.tenant_id == 0u);
}

TEST_CASE("Phy tenant_id is set from Fetch", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("tenant", "42");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.tenant_id == 42u);
}

// -------------------------------------------------------------------------
// snap / flow_id / address_space_id
// -------------------------------------------------------------------------

TEST_CASE("Phy snap is set from Fetch", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("snap", "128");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.snap == 128u);
}

TEST_CASE("Phy flow_id is set from Fetch", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("fid", "7");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.flow_id == 7u);
    CHECK(pkt.flow_id_set);
}

TEST_CASE("Phy address_space_id is set from Fetch", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("as", "5");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.address_space_id == 5u);
}

// -------------------------------------------------------------------------
// LCG determinism: same seed → same permutation order
// -------------------------------------------------------------------------

TEST_CASE("Phy perm with same seed produces same HasPayload sequence", "[phy]") {
    const uint8_t data[4] = { 1, 2, 3, 4 };

    // Run 1: seed=1, perm=4 — collect output order
    std::vector<uint8_t> run1, run2;
    {
        PhyProtocol p;
        Cake cake(2);
        cake.Store("seed", "1");
        p.Fetch(cake, true);
        cake.Store("perm", "4");
        for (int i = 0; i < 4; i++) {
            Packet pkt(cake);
            pkt.Append(data + i, 1);
            uint32_t len = 0;
            p.GetPayload(pkt, len);
            if (len) run1.push_back(*(const uint8_t*)p.GetPayload(pkt, len));
            cake.Clear("perm");
        }
        // drain remaining
        Cake cake2(2);
        while (p.HasPayload()) {
            Packet pkt2(cake2);
            uint32_t len = 0;
            const uint8_t* out = p.GetPayload(pkt2, len);
            if (out && len) run1.push_back(*out);
        }
    }

    // Run 2: same seed=1
    {
        PhyProtocol p;
        Cake cake(2);
        cake.Store("seed", "1");
        p.Fetch(cake, true);
        cake.Store("perm", "4");
        for (int i = 0; i < 4; i++) {
            Packet pkt(cake);
            pkt.Append(data + i, 1);
            uint32_t len = 0;
            p.GetPayload(pkt, len);
            if (len) run2.push_back(*(const uint8_t*)p.GetPayload(pkt, len));
            cake.Clear("perm");
        }
        Cake cake2(2);
        while (p.HasPayload()) {
            Packet pkt2(cake2);
            uint32_t len = 0;
            const uint8_t* out = p.GetPayload(pkt2, len);
            if (out && len) run2.push_back(*out);
        }
    }

    CHECK(run1 == run2);
    CHECK_FALSE(run1.empty());
}

// -------------------------------------------------------------------------
// Reverse ordering
// -------------------------------------------------------------------------

TEST_CASE("Phy rev=4 emits packets in reverse order", "[phy]") {
    PhyProtocol p;
    const uint8_t data[4] = { 10, 20, 30, 40 };
    std::vector<uint8_t> out;

    Cake cake(2);
    cake.Store("rev", "4");
    for (int i = 0; i < 4; i++) {
        Packet pkt(cake);
        pkt.Append(data + i, 1);
        uint32_t len = 0;
        const uint8_t* r = p.GetPayload(pkt, len);
        if (r && len) out.push_back(*r);
        cake.Clear("rev");
    }
    Cake cake2(2);
    while (p.HasPayload()) {
        Packet pkt2(cake2);
        uint32_t len = 0;
        const uint8_t* r = p.GetPayload(pkt2, len);
        if (r && len) out.push_back(*r);
    }

    REQUIRE(out.size() == 4u);
    CHECK(out[0] == 40);
    CHECK(out[1] == 30);
    CHECK(out[2] == 20);
    CHECK(out[3] == 10);
}

// -------------------------------------------------------------------------
// Interface IDs (a2b direction)
// -------------------------------------------------------------------------

TEST_CASE("Phy ingress/egress intf ids set from a.if/b.if in a2b direction", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("a.if", "3");
    cake.Store("b.if", "7");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.ingress_intf_id == 3);
    CHECK(pkt.egress_intf_id == 7);
}

TEST_CASE("Phy ingress/egress intf ids swapped in b2a direction", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("a.if", "3");
    cake.Store("b.if", "7");
    p.Fetch(cake, false);   // b2a: b.if -> ingress, a.if -> egress

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.ingress_intf_id == 7);
    CHECK(pkt.egress_intf_id == 3);
}

// -------------------------------------------------------------------------
// Real IP fields (a2b direction)
// -------------------------------------------------------------------------

TEST_CASE("Phy real src IPv4 address set from a.rip in a2b direction", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("a.rip", "10.0.0.1");
    cake.Store("a.rpt", "1234");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.real_src_family == AF_INET);
    CHECK(pkt.real_src_port == htons(1234));
}

TEST_CASE("Phy real dst IPv4 address set from b.rip in a2b direction", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("b.rip", "10.0.0.2");
    cake.Store("b.rpt", "5678");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.real_dst_family == AF_INET);
    CHECK(pkt.real_dst_port == htons(5678));
}

TEST_CASE("Phy real src IPv6 address set from a.rip6 in a2b direction", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("a.rip6", "::1");
    p.Fetch(cake, true);

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.real_src_family == AF_INET6);
}

TEST_CASE("Phy real src/dst swapped in b2a direction", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("b.rip", "10.0.0.2");
    cake.Store("a.rip", "10.0.0.1");
    p.Fetch(cake, false);   // b2a: b.rip -> src, a.rip -> dst

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.real_src_family == AF_INET);
    CHECK(pkt.real_dst_family == AF_INET);
}

TEST_CASE("Phy real dst IPv6 set from b.rip6 in b2a direction", "[phy]") {
    PhyProtocol p;
    Cake cake(2);
    cake.Store("a.rip6", "::1");
    p.Fetch(cake, false);   // b2a: a.rip6 -> dst

    Packet pkt(cake);
    uint32_t len = 0;
    p.GetHeader(pkt, len);
    CHECK(pkt.real_dst_family == AF_INET6);
}
