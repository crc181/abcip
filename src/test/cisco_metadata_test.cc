#include <catch2/catch_all.hpp>
#include "cake.h"
#include "cisco_metadata.h"
#include "packet.h"

#include <arpa/inet.h>

struct CiscoMetadataHdr {
    uint8_t  version;
    uint8_t  length;
    uint16_t options;
    uint16_t sgt;
    uint16_t pid;
};

// -------------------------------------------------------------------------
// Bind
// -------------------------------------------------------------------------

TEST_CASE("CiscoMetadata::Bind accepts eth-bound protocols", "[cisco]") {
    CiscoMetadataProtocol c;
    CHECK(c.Bind("ip4"));
    CHECK(c.Bind("ip6"));
    CHECK(c.Bind("arp"));
    CHECK(c.Bind("mpls"));
}

TEST_CASE("CiscoMetadata::Bind rejects non-eth protocols", "[cisco]") {
    CiscoMetadataProtocol c;
    CHECK_FALSE(c.Bind("tcp"));
    CHECK_FALSE(c.Bind("udp"));
    CHECK_FALSE(c.Bind("xyz"));
}

// -------------------------------------------------------------------------
// Fixed header fields
// -------------------------------------------------------------------------

TEST_CASE("CiscoMetadata header version is always 1", "[cisco]") {
    CiscoMetadataProtocol c;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    const CiscoMetadataHdr* h =
        reinterpret_cast<const CiscoMetadataHdr*>(c.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(h->version == 1);
}

TEST_CASE("CiscoMetadata header length is always 1", "[cisco]") {
    CiscoMetadataProtocol c;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    const CiscoMetadataHdr* h =
        reinterpret_cast<const CiscoMetadataHdr*>(c.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(h->length == 1);
}

TEST_CASE("CiscoMetadata header options field is 1", "[cisco]") {
    CiscoMetadataProtocol c;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    const CiscoMetadataHdr* h =
        reinterpret_cast<const CiscoMetadataHdr*>(c.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->options) == 1u);
}

TEST_CASE("CiscoMetadata header size is 8 bytes", "[cisco]") {
    CiscoMetadataProtocol c;
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    c.GetHeader(pkt, len);
    CHECK(len == 8u);
}

// -------------------------------------------------------------------------
// SGT encoding
// -------------------------------------------------------------------------

TEST_CASE("CiscoMetadata SGT default is 1 (from Store)", "[cisco]") {
    CiscoMetadataProtocol c;
    Cake cake(2);
    Packet pkt(cake);
    c.Store(cake, true);  // populates default sgt=1
    uint32_t len = 0;
    const CiscoMetadataHdr* h =
        reinterpret_cast<const CiscoMetadataHdr*>(c.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->sgt) == 1u);
}

TEST_CASE("CiscoMetadata SGT is set from cake", "[cisco]") {
    CiscoMetadataProtocol c;
    Cake cake(2);
    Packet pkt(cake);
    cake.Store("sgt", "0x1234");
    uint32_t len = 0;
    const CiscoMetadataHdr* h =
        reinterpret_cast<const CiscoMetadataHdr*>(c.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->sgt) == 0x1234u);
}

// -------------------------------------------------------------------------
// PID reflects bound protocol
// -------------------------------------------------------------------------

TEST_CASE("CiscoMetadata PID reflects ip4 after Bind", "[cisco]") {
    CiscoMetadataProtocol c;
    c.Bind("ip4");
    Cake cake(2);
    Packet pkt(cake);
    uint32_t len = 0;
    const CiscoMetadataHdr* h =
        reinterpret_cast<const CiscoMetadataHdr*>(c.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->pid) == 0x0800u);
}

TEST_CASE("CiscoMetadata PID overridable via cake", "[cisco]") {
    CiscoMetadataProtocol c;
    Cake cake(2);
    Packet pkt(cake);
    cake.Store("pid", "0x86dd");
    uint32_t len = 0;
    const CiscoMetadataHdr* h =
        reinterpret_cast<const CiscoMetadataHdr*>(c.GetHeader(pkt, len));
    REQUIRE(h != nullptr);
    CHECK(ntohs(h->pid) == 0x86ddu);
}
