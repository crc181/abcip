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
#include "pseudo_hdr.h"
#include "tcp.h"

#include <netinet/tcp.h>
#include <arpa/inet.h>

// Minimal PseudoHdr stub: no address lookup, just satisfies the interface.
class FakePseudoHdr : public PseudoHdr {
public:
    FakePseudoHdr() : PseudoHdr(nullptr, 0) { }
    void SetProto(int) override { }
    uint16_t GetLength() override { return sizeof(buf); }
    uint8_t* GetData(const Packet&, uint16_t) override {
        return buf;
    }
private:
    uint8_t buf[12] = { };
};

static std::pair<TcpProtocol*, TcpProtocol*> make_tcp_pair()
{
    auto* a = new TcpProtocol(new FakePseudoHdr());
    auto* b = new TcpProtocol(new FakePseudoHdr());
    a->SetPeer(b);
    b->SetPeer(a);
    return { a, b };
}

static const struct tcphdr* get_tcp_hdr(TcpProtocol* proto, Cake& cake, Packet& pkt)
{
    uint32_t len = 0;
    const uint8_t* raw = proto->GetHeader(pkt, len);
    if (!raw) return nullptr;
    return reinterpret_cast<const struct tcphdr*>(raw);
}

// -------------------------------------------------------------------------
// Bind: TcpProtocol inherits Protocol::Bind which returns true by default
// -------------------------------------------------------------------------

TEST_CASE("TcpProtocol::Bind inherits base default and returns true", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    CHECK(a->Bind("udp"));
    delete a; delete b;
}

// -------------------------------------------------------------------------
// Recv: UNA boundary — reply when ack delta reaches una
// -------------------------------------------------------------------------

TEST_CASE("TCP Recv sets reply when ack delta exactly meets una", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    // rseq=1, len=10, remoteIsn=0 → ack=11, lack=0, delta=11 >= una=10
    b->Recv(TH_ACK, 10, 1, 10);
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(b, cake, pkt);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_ACK);
    delete a; delete b;
}

TEST_CASE("TCP Recv does not set reply when ack delta is below una", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    // rseq=1, len=8, remoteIsn=0 → ack=9, lack=0, delta=9 < una=10
    b->Recv(TH_ACK, 8, 1, 10);
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(b, cake, pkt);
    REQUIRE(h != nullptr);
    CHECK_FALSE(h->th_flags & TH_ACK);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// SYN consumes one sequence number
// -------------------------------------------------------------------------

TEST_CASE("TCP SYN increments seq by 1 for next packet", "[tcp]") {
    auto [a, b] = make_tcp_pair();

    // First packet: SYN
    Cake c1(2);
    Packet p1(c1);
    c1.Store("syn", "1");
    uint32_t len = 0;
    const struct tcphdr* h1 = get_tcp_hdr(a, c1, p1);
    REQUIRE(h1 != nullptr);
    uint32_t seq1 = ntohl(h1->th_seq);

    // Second packet: no SYN, no payload — seq should be seq1+1
    Cake c2(2);
    Packet p2(c2);
    const struct tcphdr* h2 = get_tcp_hdr(a, c2, p2);
    REQUIRE(h2 != nullptr);
    uint32_t seq2 = ntohl(h2->th_seq);

    CHECK(seq2 == seq1 + 1);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// Sequence number tracking
// -------------------------------------------------------------------------

TEST_CASE("TCP sequence advances by payload length", "[tcp]") {
    auto [a, b] = make_tcp_pair();

    // SYN
    { Cake c(2); Packet p(c); c.Store("syn","1"); uint32_t l=0; a->GetHeader(p,l); }
    // SYN-ACK from b
    { Cake c(2); Packet p(c); uint32_t l=0; b->GetHeader(p,l); }
    // ACK from a
    { Cake c(2); Packet p(c); c.Store("ack","1"); uint32_t l=0; a->GetHeader(p,l); }

    const uint8_t payload[10] = {};

    Cake c1(2);
    Packet pkt1(c1);
    pkt1.Append(payload, 10);
    c1.Store("ack", "1");
    uint32_t len = 0;
    const struct tcphdr* h1 = get_tcp_hdr(a, c1, pkt1);
    REQUIRE(h1 != nullptr);
    uint32_t seq1 = ntohl(h1->th_seq);

    Cake c2(2);
    Packet pkt2(c2);
    pkt2.Append(payload, 10);
    c2.Store("ack", "1");
    const struct tcphdr* h2 = get_tcp_hdr(a, c2, pkt2);
    REQUIRE(h2 != nullptr);
    uint32_t seq2 = ntohl(h2->th_seq);

    CHECK(seq2 == seq1 + 10);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// Checksum
// -------------------------------------------------------------------------

TEST_CASE("TCP checksum is non-zero for SYN packet", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake cake(2);
    Packet pkt(cake);
    cake.Store("syn", "1");
    uint32_t len = 0;
    const struct tcphdr* hdr = get_tcp_hdr(a, cake, pkt);
    REQUIRE(hdr != nullptr);
    CHECK(hdr->th_sum != 0);
    delete a; delete b;
}
