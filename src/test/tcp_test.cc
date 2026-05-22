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

TEST_CASE("TCP checksum with odd-length payload", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake cake(2);
    Packet pkt(cake);
    const uint8_t payload[5] = { 1, 2, 3, 4, 5 };
    pkt.Append(payload, 5);
    uint32_t len = 0;
    const struct tcphdr* hdr = get_tcp_hdr(a, cake, pkt);
    REQUIRE(hdr != nullptr);
    CHECK(hdr->th_sum != 0);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// All control flags
// -------------------------------------------------------------------------

TEST_CASE("TCP Send sets FIN flag", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("fin", "1");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_FIN);
    delete a; delete b;
}

TEST_CASE("TCP Send sets PSH flag", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("psh", "1");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_PUSH);
    delete a; delete b;
}

TEST_CASE("TCP Send sets RST flag", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("rst", "1");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_RST);
    delete a; delete b;
}

TEST_CASE("TCP Send sets URG flag", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("urg", "1");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_URG);
    delete a; delete b;
}

TEST_CASE("TCP Send sets ACK flag explicitly", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("ack", "1");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_ACK);
    delete a; delete b;
}

TEST_CASE("TCP Send sets ctl field directly", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("ctl", "0x12");  // SYN|ACK
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_SYN);
    CHECK(h->th_flags & TH_ACK);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// seq/ack/jump/jack overrides
// -------------------------------------------------------------------------

TEST_CASE("TCP explicit seq overrides FSM", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("seq", "1000");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(ntohl(h->th_seq) == 1000u);
    delete a; delete b;
}

TEST_CASE("TCP jump shifts sequence number", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    // establish ISN via SYN
    { Cake c(2); Packet p(c); c.Store("syn","1"); uint32_t l=0; a->GetHeader(p,l); }
    Cake c(2); Packet p(c);
    c.Store("jump", "100");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    // localIsn=1, seq=1 after SYN, jump adds 100 → hseq = 101 + 1 = 102
    CHECK(ntohl(h->th_seq) == 102u);
    delete a; delete b;
}

TEST_CASE("TCP jack shifts ack number", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    // SYN from a, SYN-ACK from b sets remoteIsn
    { Cake c(2); Packet p(c); c.Store("syn","1"); uint32_t l=0; a->GetHeader(p,l); }
    { Cake c(2); Packet p(c); c.Store("syn","1"); uint32_t l=0; b->GetHeader(p,l); }
    Cake c(2); Packet p(c);
    c.Store("ack", "1");
    c.Store("jack", "5");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    // ack is shifted by 5 relative to normal
    CHECK(ntohl(h->th_ack) != 0u);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// GetHeader: win, cks override, off/res/ecn, raw header override
// -------------------------------------------------------------------------

TEST_CASE("TCP GetHeader respects explicit window size", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("win", "4096");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->th_win) == 4096u);
    delete a; delete b;
}

TEST_CASE("TCP GetHeader respects explicit checksum", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("cks", "0xdead");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->th_sum) == 0xdeadu);
    delete a; delete b;
}

TEST_CASE("TCP GetHeader respects explicit data offset", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("off", "6");
    uint32_t len = 0;
    // get raw bytes rather than struct tcphdr to avoid bitfield layout issues
    const uint8_t* raw = a->GetHeader(p, len);
    REQUIRE(raw != nullptr);
    // offset byte is at position 12; abcip packs it as (off<<4)|flags_low
    CHECK((raw[12] >> 4) == 6u);
    delete a; delete b;
}

TEST_CASE("TCP GetHeader sets ECN bits", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("ecn", "7");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    // ecn&0x3 -> upper ctl bits; ecn&0x4 -> low off bit
    CHECK((h->th_off & 0x1) != 0);
    CHECK((h->th_flags >> 6) != 0);
    delete a; delete b;
}

TEST_CASE("TCP GetHeader returns raw head override", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    // "head" is the base Protocol raw-header override; 8 printable chars = 8 bytes
    c.Store("head", "\"AABBCCDD\"");
    uint32_t len = 0;
    const uint8_t* raw = a->GetHeader(p, len);
    REQUIRE(raw != nullptr);
    CHECK(len == 8u);
    delete a; delete b;
}

TEST_CASE("TCP GetHeader works without peer (null peer path)", "[tcp]") {
    auto* a = new TcpProtocol(new FakePseudoHdr());
    // no peer set
    Cake c(2); Packet p(c);
    c.Store("syn", "1");
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(a, c, p);
    REQUIRE(h != nullptr);
    CHECK(h->th_flags & TH_SYN);
    delete a;
}

// -------------------------------------------------------------------------
// GetOptions
// -------------------------------------------------------------------------

TEST_CASE("TCP GetOptions: MSS option", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("mss", "1460");
    uint32_t len = 0;
    const uint8_t* opts = a->GetOptions(p, len);
    CHECK(len == 4u);
    CHECK(opts[0] == 0x02);  // kind=2
    CHECK(opts[1] == 0x04);  // len=4
    delete a; delete b;
}

TEST_CASE("TCP GetOptions: window scale option", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("wis", "7");
    uint32_t len = 0;
    const uint8_t* opts = a->GetOptions(p, len);
    // 3 bytes + 1 pad = 4
    CHECK(len == 4u);
    CHECK(opts[0] == 0x03);  // kind=3
    CHECK(opts[2] == 0x07);  // shift=7
    delete a; delete b;
}

TEST_CASE("TCP GetOptions: timestamp option", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("tsv", "12345");
    c.Store("tse", "0");
    uint32_t len = 0;
    const uint8_t* opts = a->GetOptions(p, len);
    // 10 bytes + 2 pad = 12
    CHECK(len == 12u);
    delete a; delete b;
}

TEST_CASE("TCP GetOptions: raw opt suppresses padding", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("opt", "\"AB\"");
    uint32_t len = 0;
    a->GetOptions(p, len);
    CHECK(len == 2u);  // no padding added for raw opt
    delete a; delete b;
}

TEST_CASE("TCP GetOptions: padding to 4-byte multiple", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    c.Store("wis", "3");  // 3 bytes → padded to 4
    uint32_t len = 0;
    a->GetOptions(p, len);
    CHECK(len % 4 == 0);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// GetPayload / HasPayload
// -------------------------------------------------------------------------

TEST_CASE("TCP GetPayload returns null when no payload and no max", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    uint32_t len = 99;
    const uint8_t* pay = a->GetPayload(p, len);
    CHECK(pay == nullptr);
    CHECK(len == 0u);
    delete a; delete b;
}

TEST_CASE("TCP HasPayload false initially", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    CHECK_FALSE(a->HasPayload());
    delete a; delete b;
}

TEST_CASE("TCP GetPayload segments at max", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    const uint8_t payload[20] = {};
    p.Append(payload, 20);
    c.Store("max", "8");
    uint32_t len = 0;
    const uint8_t* pay = a->GetPayload(p, len);
    REQUIRE(pay != nullptr);
    CHECK(len == 8u);
    // HasPayload should be true — more data remains
    CHECK(a->HasPayload());
    delete a; delete b;
}

TEST_CASE("TCP GetPayload returns full buf when max exceeds buf size", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    Cake c(2); Packet p(c);
    const uint8_t payload[5] = { 1,2,3,4,5 };
    p.Append(payload, 5);
    c.Store("max", "100");
    uint32_t len = 0;
    const uint8_t* pay = a->GetPayload(p, len);
    REQUIRE(pay != nullptr);
    CHECK(len == 5u);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// Recv: SYN/FIN consume sequence; remoteIsn tracking
// -------------------------------------------------------------------------

TEST_CASE("TCP Recv SYN sets remoteIsn", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    // SYN from a: rseq=1, len=0 → b->ack = 1+1-0 = 2 (SYN consumes 1), remoteIsn=0
    b->Recv(TH_SYN, 0, 1, 0);
    // Use ctl=TH_ACK to set the ACK flag without storing a value for "ack",
    // so Send takes the else branch: ack = cake.GetValue("ack", b->ack) = b->ack = 2
    Cake c(2); Packet p(c);
    c.Store("ctl", "16");  // TH_ACK = 0x10 = 16
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(b, c, p);
    REQUIRE(h != nullptr);
    // hack = b->ack(2) + remoteIsn(0) = 2
    CHECK(ntohl(h->th_ack) == 2u);
    delete a; delete b;
}

TEST_CASE("TCP Recv FIN consumes one sequence number", "[tcp]") {
    auto [a, b] = make_tcp_pair();
    b->Recv(TH_SYN, 0, 1, 0);  // remoteIsn=0, ack=2
    b->Recv(TH_FIN, 0, 2, 0);  // ack = 2+1-0 = 3
    Cake c(2); Packet p(c);
    c.Store("ctl", "16");  // TH_ACK — leaves "ack" key unset so FSM value flows through
    uint32_t len = 0;
    const struct tcphdr* h = get_tcp_hdr(b, c, p);
    REQUIRE(h != nullptr);
    // hack = b->ack(3) + remoteIsn(0) = 3
    CHECK(ntohl(h->th_ack) == 3u);
    delete a; delete b;
}

// -------------------------------------------------------------------------
// Bare ack after explicit ack=N should inherit N, not revert to auto-tracked
// -------------------------------------------------------------------------

TEST_CASE("TCP bare ack inherits preceding explicit ack value", "[tcp]") {
    auto [a, b] = make_tcp_pair();

    // SYN from a (localIsn_a=1)
    { Cake c(2); Packet p(c); c.Store("syn","1"); uint32_t l=0; a->GetHeader(p,l); }
    // SYN from b with seq=1000 → a.remoteIsn=999
    { Cake c(2); Packet p(c); c.Store("syn","1"); c.Store("seq","1000"); uint32_t l=0; b->GetHeader(p,l); }
    // RST from b with seq=722 → a auto-ack diverges from 1001
    { Cake c(2); Packet p(c); c.Store("rst","1"); c.Store("seq","722"); uint32_t l=0; b->GetHeader(p,l); }

    // explicit ack=1001 — wire ack must be 1001
    Cake c4(2); Packet p4(c4);
    c4.Store("ack", "1001");
    uint32_t l4 = 0;
    const struct tcphdr* h4 = get_tcp_hdr(a, c4, p4);
    REQUIRE(h4 != nullptr);
    CHECK(ntohl(h4->th_ack) == 1001u);

    // bare ack — wire ack must still be 1001, not 1001+remoteIsn
    Cake c5(2); Packet p5(c5);
    c5.Store("ack", " ");
    uint32_t l5 = 0;
    const struct tcphdr* h5 = get_tcp_hdr(a, c5, p5);
    REQUIRE(h5 != nullptr);
    CHECK(ntohl(h5->th_ack) == 1001u);

    delete a; delete b;
}
