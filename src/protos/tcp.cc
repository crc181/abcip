//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2013 Charles R. Combs
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
// tcp stuff
//-------------------------------------------------------------------------

#include <netinet/tcp.h>

#include "cake.h"
#include "pseudo_hdr.h"
#include "tcp.h"

// FIXTHIS layer should be added to default addresses and ports
#define TCP_A "48620"
#define TCP_B     "8"

#define TCP_URG 0x20
#define TCP_ACK 0x10
#define TCP_PSH 0x08
#define TCP_RST 0x04
#define TCP_SYN 0x02
#define TCP_FIN 0x01

#define DEF_WIN 8192

static const char* s_type = "tcp";

// system defined tcphdr is too cumbersome:
// typedef struct tcphdr TcpHdr;
// so we roll our own wheel, and 
// mix metaphors for good measure:

struct TcpHdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off;
    uint8_t  ctl;
    uint16_t win;
    uint16_t cks;
    uint16_t urp;
};

class TcpImpl {
public:
    void Send(const Packet&, uint32_t, uint8_t&, uint32_t&, uint32_t&);
    void Recv(uint8_t, uint32_t, uint32_t, uint32_t);

public:
    TcpHdr h;
    PseudoHdr* ph;
    uint16_t last;
    string opt;
    string buf;

    uint32_t localIsn, remoteIsn;
    uint32_t seq, ack, lack;

    bool reply;
};

TcpProtocol::TcpProtocol (PseudoHdr* ph) : Protocol(s_type) {
    my = new TcpImpl;
    my->ph = ph;
    ph->SetProto(IPPROTO_TCP);

    my->seq = my->localIsn = 0;
    my->ack = my->remoteIsn = 0;

    my->reply = false;
    my->last = 0;
    my->lack = 0;
}

TcpProtocol::~TcpProtocol () {
    delete my->ph;
    delete my;
}

void TcpProtocol::Store (Cake& cake, bool a2b) {
    cake.Store("src", a2b ? TCP_A : TCP_B, true);
    cake.Store("dst", a2b ? TCP_B : TCP_A, true);

    Protocol::Store(cake, a2b);
    my->h.win = htons(DEF_WIN);
}

static inline void Set (uint8_t& ctl, uint8_t f) {
    ctl |= f;
}

static inline bool IsSet (uint8_t& ctl, uint8_t f) {
    return (ctl & f) != 0;
}

void TcpImpl::Send (
    const Packet& p, uint32_t len, uint8_t& ctl,
    uint32_t& hseq, uint32_t& hack
) {
    ctl = 0;

    if ( p.cake.IsSet("ack") ) Set(ctl, TCP_ACK);
    if ( p.cake.IsSet("fin") ) Set(ctl, TCP_FIN);
    if ( p.cake.IsSet("psh") ) Set(ctl, TCP_PSH);
    if ( p.cake.IsSet("rst") ) Set(ctl, TCP_RST);
    if ( p.cake.IsSet("syn") ) Set(ctl, TCP_SYN);
    if ( p.cake.IsSet("urg") ) Set(ctl, TCP_URG);

    ctl = p.cake.GetValue("ctl", ctl);
    seq = p.cake.GetValue("seq", seq);

    if ( IsSet(ctl, TCP_SYN) ) { 
        // we start at 1 to avoid wireshark weirdness
        if ( !p.cake.IsSet("seq") ) seq = 1;
        localIsn = seq;
        seq = 0;
    }   

    // FIXTHIS localIsn handling should simplified
    // above and below

    if ( p.cake.IsSet("seq") ) {
        localIsn = p.cake.GetValue("seq", 0);
        seq = 0;
    }

    if ( !reply && !IsSet(ctl, TCP_ACK) )
        ack = p.cake.GetValue("ack", 0);
    else
        ack = p.cake.GetValue("ack", ack);

    int32_t jump = p.cake.GetValue("jump", (int32_t)0);
    seq += jump;

    jump = p.cake.GetValue("jack", (int32_t)0);
    ack += jump;

    hseq = seq + localIsn;
    hack = lack = ack;

    if ( !p.cake.GetValue("ack", 0) )
        hack += remoteIsn;

    if ( IsSet(ctl, TCP_SYN) ) seq++;
    if ( IsSet(ctl, TCP_FIN) ) seq++;

    seq += len;

    if ( reply ) {
        Set(ctl, TCP_ACK);
        reply = false;
    }
}

void TcpProtocol::Recv (
    uint8_t ctl, uint32_t len, uint32_t rseq, uint32_t una
) {
    my->Recv(ctl, len, rseq, una);
}

void TcpImpl::Recv (
    uint8_t ctl, uint32_t len, uint32_t rseq, uint32_t una
) {
    if ( IsSet(ctl, TCP_SYN) ) {
        // -1 to satisfy wireshark weirdness (see above)
        remoteIsn = rseq - 1;
    }

    if ( IsSet(ctl, TCP_SYN) ) len++;
    if ( IsSet(ctl, TCP_FIN) ) len++;

    ack = rseq + len - remoteIsn;

    if ( una && (int)(ack - lack) > (int)una )
        reply = true;
}

const uint8_t* TcpProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    uint8_t ctl;
    uint32_t seq, ack;
    uint32_t slen = p.Length() - my->opt.length();
    uint32_t una = p.cake.GetValue("una", 0);

    my->Send(p, slen, ctl, seq, ack);
    ((TcpProtocol*)GetPeer())->Recv(ctl, slen, seq, una);

    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    my->h.src = htons(SrcPort(p));
    my->h.dst = htons(DstPort(p));

    my->h.urp = (uint16_t)htons(p.cake.GetValue("urg", 0));

    int off = (sizeof(my->h) + my->opt.length()) >> 2;
    int res = p.cake.GetValue("res", 0);
    int ecn = p.cake.GetValue("ecn", 0);

    my->h.off = (int)p.cake.GetValue("off", off);
    my->h.off = (my->h.off << 4) | ((res&0x7) << 1) | (ecn&0x4?1:0);

    my->h.ctl = ctl;
    my->h.ctl |= (ecn & 0x3) << 6;

    my->h.seq = htonl(seq);
    my->h.ack = htonl(ack);

    if ( p.cake.IsSet("win") )
        my->h.win = htons(p.cake.GetValue("win", 0));

    if ( !p.cake.IsSet("cks") ) Checksum(p);
    else my->h.cks = htons((uint16_t)p.cake.GetValue("cks", 0));

    len = sizeof(my->h);
    return (uint8_t*)&my->h;
}

// opt  kind len fields            comments
// mss   2    4  mss(16)           syn only
// wis   3    3  shift(8)          syn only
// ts    8   10  tsv(32), tse(32)  all segments, tse non-zero iff ack set
const uint8_t* TcpProtocol::GetOptions (
    const Packet& p, uint32_t& len
) {
    my->opt.clear();

    if ( p.cake.IsSet("mss") ) {
        uint16_t mss = (uint16_t)p.cake.GetValue("mss", 0);
        uint16_t x[2] = { htons(0x0204), htons(mss) };
        for (unsigned i = 0; i < sizeof(x); i++) my->opt += ((char*)x)[i];
    }
    if ( p.cake.IsSet("wis") ) {
        char x[3] = { 3, 3, (uint8_t)p.cake.GetValue("wis", 0) };
        for (unsigned i = 0; i < sizeof(x); i++) my->opt += x[i];
    }
    if ( p.cake.IsSet("tsv") || p.cake.IsSet("tse") ) {
        uint32_t tsv = p.cake.GetValue("tsv", 0);
        uint32_t tse = p.cake.GetValue("tse", 0);
        uint32_t x[3] = { htonl(0x080a), htonl(tsv), htonl(tse) };
        for (unsigned i = 2; i < sizeof(x); i++) my->opt += ((char*)x)[i];
    }
    // add user opts w/o padding or
    if ( p.cake.IsSet("opt") ) my->opt += p.cake.GetValue("opt");
    // pad as necessary to 32-bit multiple
    else while ( my->opt.length() % 4 ) my->opt += '\0';

    len = my->opt.length();
    return (uint8_t*)my->opt.data();
}

const uint8_t* TcpProtocol::GetPayload (
    const Packet& p, uint32_t& len
) {
    if ( my->last ) {
        my->buf.erase(0, my->last);
        my->last = 0;
    }
    uint16_t max = p.cake.GetValue("max", 0);

    if ( !max && !my->buf.length() ) {
        len = 0;
        return NULL;
    }
    my->buf.append((char*)p.Data(), p.Length());

    if ( !max || my->buf.length() <= max ) {
        len = my->last = my->buf.length();
        return (uint8_t*)my->buf.data();
    }
    len = my->last = max;
    return (uint8_t*)my->buf.data();
}

bool TcpProtocol::HasPayload () {
    return ( my->reply || my->buf.length() > my->last );
}

void TcpProtocol::Checksum (const Packet& p) {
    uint16_t olen = my->opt.length();
    const uint8_t* opts = (uint8_t*)my->opt.data();

    uint16_t dlen = p.Length();
    const uint8_t* data = p.Data();

    uint16_t tlen = sizeof(my->h) + dlen;

    uint16_t oadj = 0;
    uint8_t oend[2] = { 0, 0 };
    if ( olen & 0x1 ) oend[oadj++] = opts[--olen];

    uint16_t dadj = 0;
    uint8_t dend[2] = { 0, 0 };  // alignment
    if ( dlen & 0x1 ) dend[dadj++] = data[--dlen];

    CheckField f[] = {
        // pseudoheader
        { (uint16_t*)my->ph->GetData(p, tlen), my->ph->GetLength()>>1 },
        // tcp header
        { (uint16_t*)&my->h, sizeof(my->h)>>1 },
        // padded payload
        { (uint16_t*)data, dlen>>1 },  // alignment
        { (uint16_t*)dend, dadj },
        { NULL, 0 }
    };
    my->h.cks = 0x0000;
    my->h.cks = Protocol::Checksum(f);
}

//-------------------------------------------------------------------------

static Field s_fields[] = {
    { FT_CFG, "a", "u16", "set host a port" },
    { FT_CFG, "b", "u16", "set host b port" },
    { FT_PKT, "opt", "s*", "set option octets" },
    { FT_PKT, "tsv", "u32", "set timestamp value" },
    { FT_PKT, "tse", "u32", "set timestamp echo" },
    { FT_PKT, "src", "u16", "set source port" },
    { FT_PKT, "dst", "u16", "set source port" },
    { FT_PKT, "urg", "u16", "set urgent ptr" },
    { FT_PKT, "cks", "u16", "set checksum" },
    { FT_PKT, "mss", "u16", "set max seg size option" },
    { FT_PKT, "wis", "u8", "set window scale option" },
    { FT_PKT, "off", "u4", "set data offset" },
    { FT_PKT, "res", "u3", "set reserved bits" },
    { FT_PKT, "ecn", "u3", "set ecn bits" },
    { FT_PKT, "seq", "u32", "set sequence number" },
    { FT_PKT, "ack", "u32", "set ack number" },
    { FT_PKT, "jump", "i32", "seq delta" },
    { FT_PKT, "jack", "i32", "ack delta" },
    { FT_PKT, "max", "u32", "segment at max" },
    { FT_PKT, "una", "u32", "ack every una octets" },
    { FT_PKT, "win", "u16", "set window size" },
    { FT_PKT, "ctl", "u8", "set control bits" },
    { FT_PKT, "syn", "u1", "set SYN flag" },
    { FT_PKT, "fin", "u1", "set FIN flag" },
    { FT_PKT, "ack", "u1", "set ACK flag" },
    { FT_PKT, "rst", "u1", "set RST flag" },
    { FT_PKT, "psh", "u1", "set PSH flag" },
    { FT_PKT, "urg", "u1", "set URG flag" },
    { FT_MAX, NULL, NULL, NULL }
};

class TcpPimp : public Pimp {
public:
    TcpPimp() : Pimp(s_type, s_fields) { };

    Protocol* New(PseudoHdr* ph) {
        return new TcpProtocol(ph);
    };
};

Pimp* TcpProtocol::GetPimp () { return new TcpPimp; }

