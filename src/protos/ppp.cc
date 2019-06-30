/*
 * provides encapsulation for ip4 and ip6
 */

#include <ostream>

#include "cake.h"
#include "ppp.h"

#define PPP_IP4 0x0021
#define PPP_IP6 0x0057

static const char* s_type = "ppp";

struct PppHdr
{
    uint16_t hdr;
};

class PppImpl
{
    public:
    PppHdr h;
};

PppProtocol::PppProtocol ():Protocol (s_type)
{
    my = new PppImpl;
}

PppProtocol::~PppProtocol ()
{
    delete my;
}

bool PppProtocol::Bind (const string& type) {
    if ( type == "ip4" )
        my->h.hdr = htons((uint16_t)PPP_IP4);

    else if ( type == "ip6" )
        my->h.hdr = htons((uint16_t)PPP_IP6);

    else
        return false;

    return true;
}

const uint8_t* PppProtocol::GetHeader (
    Packet& p, uint32_t& len
) {
    const uint8_t* raw = Protocol::GetHeader(p, len);
    if ( raw ) return raw;

    len = sizeof(my->h);
    return (uint8_t *)&my->h;
}

//-------------------------------------------------------------------------

class PppPimp : public Pimp {
public:
    PppPimp() : Pimp(s_type, nullptr) { }

    Protocol* New(PseudoHdr*) override {
        return new PppProtocol();
    }

    void HelpBind(ostream&) override;
};

void PppPimp::HelpBind (ostream& out) {
    out << Type () << " -> ip4|ip6" << endl;
}

Pimp* PppProtocol::GetPimp () { return new PppPimp; }

