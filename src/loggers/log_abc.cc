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

//-------------------------------------------------------------------------
// log_abc: Snort logger plugin that emits an abcip .abc script reproducing
// decoded traffic.  One d()/c() preamble per new flow; a()/b() per packet.
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdio>
#include <map>
#include <string>
#include <sstream>

#include <events/event.h>
#include <framework/logger.h>
#include <framework/module.h>
#include <protocols/eth.h>
#include <protocols/geneve.h>
#include <protocols/gre.h>
#include <protocols/icmp4.h>
#include <protocols/ip.h>
#include <protocols/ipv4.h>
#include <protocols/ipv6.h>
#include <protocols/layer.h>
#include <protocols/mpls.h>
#include <protocols/packet.h>
#include <protocols/protocol_ids.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>
#include <protocols/vlan.h>
#include <sfip/sf_ip.h>

using namespace snort;
using namespace std;

#define S_NAME "log_abc"
#define S_HELP "emit abcip .abc script reproducing captured traffic"

//-------------------------------------------------------------------------
// flow key and state
//-------------------------------------------------------------------------

struct AbcFlowKey
{
    string src_ip;
    string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;

    bool operator<(const AbcFlowKey& o) const
    {
        if (src_ip != o.src_ip) return src_ip < o.src_ip;
        if (dst_ip != o.dst_ip) return dst_ip < o.dst_ip;
        if (src_port != o.src_port) return src_port < o.src_port;
        if (dst_port != o.dst_port) return dst_port < o.dst_port;
        return proto < o.proto;
    }
};

struct AbcFlowState
{
    string ctx;      // context name, empty = default (first flow)
    string a_ip;
    uint16_t a_port = 0;
};

static THREAD_LOCAL map<AbcFlowKey, AbcFlowState>* s_flows = nullptr;
static THREAD_LOCAL unsigned s_flow_count = 0;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static string ip_str(const SfIp* ip)
{
    if (!ip) return "";
    SfIpString buf;
    ip->ntop(buf);
    return buf;
}

static string mac_str(const uint8_t* m)
{
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
        m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

static string hex_payload(const uint8_t* data, unsigned len)
{
    if (!len) return "";
    string s = "\"|";
    for (unsigned i = 0; i < len; i++)
    {
        char h[4];
        snprintf(h, sizeof(h), "%02x", data[i]);
        if (i) s += ' ';
        s += h;
    }
    s += "|\"";
    return s;
}

// Build the abcip stack string by walking p->layers[].
static string build_stack(const Packet* p)
{
    string stack;

    for (int i = 0; i < p->num_layers; i++)
    {
        const Layer& lyr = p->layers[i];
        string name;

        switch (lyr.prot_id)
        {
        // ETHERTYPE_NOT_SET, IP, and HOPOPTS all share value 0; treat as skip
        case ProtocolId::ETHERTYPE_NOT_SET:
            continue;

        case ProtocolId::FINISHED_DECODE:
            continue;

        // link layer
        case ProtocolId::ETHERNET_802_3:
        case ProtocolId::ETHERNET_802_11:
            name = "eth"; break;

        case ProtocolId::ETHERTYPE_8021Q:
        case ProtocolId::ETHERTYPE_8021AD:
            name = "vlan"; break;

        case ProtocolId::ETHERTYPE_CISCO_META:
            name = "cisco"; break;

        case ProtocolId::ETHERTYPE_MPLS_UNICAST:
        case ProtocolId::ETHERTYPE_MPLS_MULTICAST:
            name = "mpls"; break;

        case ProtocolId::ETHERTYPE_PPPOE_SESS:
        case ProtocolId::ETHERTYPE_PPPOE_DISC:
            name = "pppoe"; break;

        case ProtocolId::ETHERTYPE_PPP:
            name = "ppp"; break;

        // network layer — ETHERTYPE_IPV4 for eth-encapped; IPIP for tunnel-encapped
        case ProtocolId::ETHERTYPE_IPV4:
        case ProtocolId::IPIP:
            name = "ip4"; break;

        case ProtocolId::ETHERTYPE_IPV6:
        case ProtocolId::IPV6:
            name = "ip6"; break;

        case ProtocolId::ETHERTYPE_ARP:
            name = "arp"; break;

        // tunnel
        case ProtocolId::GRE:
            name = "gre"; break;

        case ProtocolId::GENEVE:
            name = "geneve"; break;

        case ProtocolId::VXLAN:
            name = "vxlan"; break;

        // transport
        case ProtocolId::TCP:
            name = "tcp"; break;

        case ProtocolId::UDP:
            name = "udp"; break;

        case ProtocolId::ICMPV4:
            name = "icmp4"; break;

        case ProtocolId::ICMPV6:
            name = "icmp6"; break;

        // IPv6 extension headers — DSTOPTS/ROUTING/FRAGMENT have unique values
        case ProtocolId::DSTOPTS:
            name = "dst6"; break;

        case ProtocolId::ROUTING:
            name = "rte6"; break;

        case ProtocolId::FRAGMENT:
            name = "frag6"; break;

        default:
            name = "raw"; break;
        }

        if (!stack.empty()) stack += ':';
        stack += name;
    }

    if (stack.empty()) stack = "raw";
    return stack;
}

//-------------------------------------------------------------------------
// per-packet emission
//-------------------------------------------------------------------------

static void emit_preamble(const Packet* p, AbcFlowState& fs,
    const string& src_ip, const string& dst_ip,
    uint16_t src_port, uint16_t dst_port)
{
    string stack = build_stack(p);
    string ctx = fs.ctx.empty() ? "" : fs.ctx + ":";

    // d() — define stack
    printf("%sd ( stack=\"%s\" )\n", ctx.c_str(), stack.c_str());

    // c() — configure addresses and ports
    // eth addresses
    if (const auto* eh = layer::get_eth_layer(p))
    {
        string a_mac = mac_str(eh->ether_src);
        string b_mac = mac_str(eh->ether_dst);
        printf("%sc ( eth:a=\"%s\", eth:b=\"%s\"", ctx.c_str(),
            a_mac.c_str(), b_mac.c_str());
    }
    else
    {
        printf("%sc (", ctx.c_str());
    }

    // IP addresses
    if (!src_ip.empty() && !dst_ip.empty())
    {
        bool is6 = (p->ptrs.ip_api.is_ip6());
        const char* proto = is6 ? "ip6" : "ip4";
        printf(", %s:a=\"%s\", %s:b=\"%s\"",
            proto, src_ip.c_str(), proto, dst_ip.c_str());
    }

    // ports
    if (src_port || dst_port)
    {
        const char* tproto = p->is_tcp() ? "tcp" : "udp";
        printf(", %s:a=%u, %s:b=%u",
            tproto, src_port, tproto, dst_port);
    }

    printf(" )\n\n");

    fs.a_ip = src_ip;
    fs.a_port = src_port;
}

static void emit_tcp_packet(const Packet* p, const string& ctx, bool a2b)
{
    const tcp::TCPHdr* h = p->ptrs.tcph;
    if (!h) return;

    const char* cmd = a2b ? "a" : "b";
    string pfx = ctx.empty() ? "" : ctx + ":";

    printf("%s%s ( ", pfx.c_str(), cmd);

    // flags
    bool first = true;
    auto sep = [&]() { if (!first) printf(", "); first = false; };

    if (h->th_flags & TH_SYN)  { sep(); printf("syn"); }
    if (h->th_flags & TH_FIN)  { sep(); printf("fin"); }
    if (h->th_flags & TH_RST)  { sep(); printf("rst"); }
    if (h->th_flags & TH_ACK)  { sep(); printf("ack"); }
    if (h->th_flags & TH_PUSH) { sep(); printf("psh"); }
    if (h->th_flags & TH_URG)  { sep(); printf("urg"); }

    sep(); printf("seq=%u", h->seq());
    sep(); printf("ack=%u", h->ack());
    sep(); printf("win=%u", h->win());

    if (h->urp())
    { sep(); printf("urg=%u", h->urp()); }

    if (p->dsize)
    {
        string pay = hex_payload(p->data, p->dsize);
        sep(); printf("raw:pay=%s", pay.c_str());
    }

    printf(" )\n");
}

static void emit_udp_packet(const Packet* p, const string& ctx, bool a2b)
{
    const char* cmd = a2b ? "a" : "b";
    string pfx = ctx.empty() ? "" : ctx + ":";

    printf("%s%s ( ", pfx.c_str(), cmd);

    if (p->dsize)
    {
        string pay = hex_payload(p->data, p->dsize);
        printf("raw:pay=%s", pay.c_str());
    }

    printf(" )\n");
}

static void emit_icmp4_packet(const Packet* p, const string& ctx, bool a2b)
{
    const icmp::ICMPHdr* h = p->ptrs.icmph;
    if (!h) return;

    const char* cmd = a2b ? "a" : "b";
    string pfx = ctx.empty() ? "" : ctx + ":";

    printf("%s%s ( icmp4:type=%u, icmp4:code=%u",
        pfx.c_str(), cmd,
        static_cast<uint8_t>(h->type),
        static_cast<uint8_t>(h->code));

    if (p->dsize)
    {
        string pay = hex_payload(p->data, p->dsize);
        printf(", raw:pay=%s", pay.c_str());
    }

    printf(" )\n");
}

static void emit_raw_packet(const Packet* p, const string& ctx, bool a2b)
{
    const char* cmd = a2b ? "a" : "b";
    string pfx = ctx.empty() ? "" : ctx + ":";

    printf("%s%s (", pfx.c_str(), cmd);

    if (p->dsize)
    {
        string pay = hex_payload(p->data, p->dsize);
        printf(" raw:pay=%s", pay.c_str());
    }

    printf(" )\n");
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class LogAbcModule : public Module
{
public:
    LogAbcModule() : Module(S_NAME, S_HELP) { }
};

//-------------------------------------------------------------------------
// logger
//-------------------------------------------------------------------------

class LogAbc : public Logger
{
public:
    LogAbc() = default;

    void open() override;
    void close() override;
    void log(Packet*, const char*, Event*) override;
};

void LogAbc::open()
{
    if (!s_flows)
        s_flows = new map<AbcFlowKey, AbcFlowState>;
    s_flow_count = 0;
}

void LogAbc::close()
{
    delete s_flows;
    s_flows = nullptr;
}

void LogAbc::log(Packet* p, const char*, Event*)
{
    if (!p || !s_flows)
        return;

    // extract IP src/dst and transport ports
    string src_ip, dst_ip;
    uint16_t src_port = 0, dst_port = 0;

    if (p->ptrs.ip_api.is_ip())
    {
        src_ip = ip_str(p->ptrs.ip_api.get_src());
        dst_ip = ip_str(p->ptrs.ip_api.get_dst());
    }

    if (p->ptrs.tcph)
    {
        src_port = p->ptrs.tcph->src_port();
        dst_port = p->ptrs.tcph->dst_port();
    }
    else if (p->ptrs.udph)
    {
        src_port = p->ptrs.udph->src_port();
        dst_port = p->ptrs.udph->dst_port();
    }

    // build canonical flow key (lower IP:port first)
    AbcFlowKey fwd { src_ip, dst_ip, src_port, dst_port,
        static_cast<uint8_t>(p->get_ip_proto_next()) };
    AbcFlowKey rev { dst_ip, src_ip, dst_port, src_port,
        static_cast<uint8_t>(p->get_ip_proto_next()) };

    bool a2b = true;
    auto it = s_flows->find(fwd);
    if (it == s_flows->end())
    {
        it = s_flows->find(rev);
        if (it != s_flows->end())
            a2b = false;
    }

    if (it == s_flows->end())
    {
        // new flow
        AbcFlowState fs;
        s_flow_count++;
        fs.ctx = (s_flow_count == 1) ? "" : ("sess" + to_string(s_flow_count));

        emit_preamble(p, fs, src_ip, dst_ip, src_port, dst_port);
        (*s_flows)[fwd] = fs;
        it = s_flows->find(fwd);
        a2b = true;
    }

    AbcFlowState& fs = it->second;

    if (p->is_tcp())
        emit_tcp_packet(p, fs.ctx, a2b);
    else if (p->is_udp())
        emit_udp_packet(p, fs.ctx, a2b);
    else if (p->ptrs.icmph)
        emit_icmp4_packet(p, fs.ctx, a2b);
    else
        emit_raw_packet(p, fs.ctx, a2b);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new LogAbcModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* log_ctor(Module*)
{ return new LogAbc; }

static void log_dtor(Logger* l)
{ delete l; }

static LogApi log_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        S_HELP,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__LOG,
    log_ctor,
    log_dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &log_api.base,
    nullptr
};
