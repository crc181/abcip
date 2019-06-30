#ifndef __PPP_H__
#define __PPP_H__

#include "protocol.h"

class PppProtocol:public Protocol
{
  public:
    PppProtocol();
    ~PppProtocol() override;

    bool Bind(const std::string&) override;
    const uint8_t* GetHeader(Packet&, uint32_t&) override;

    static Pimp* GetPimp();

  private:
    class PppImpl * my;
};

#ifdef __PROTOTOOL_TAG__
#include "ppp.h"
PROTOTOOL_NEW(PppProtocol);
#endif

#endif
