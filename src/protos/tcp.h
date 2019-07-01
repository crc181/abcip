//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2017 Charles R. Combs
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

#ifndef __TCP_H__
#define __TCP_H__

#include "protocol.h"

class TcpProtocol : public Protocol {
public:
    TcpProtocol(PseudoHdr*);
    ~TcpProtocol() override;

    void Store(Cake&, bool) override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;
    const uint8_t* GetOptions(const Packet&, uint32_t&) override;
    const uint8_t* GetPayload(const Packet&, uint32_t&) override;

    bool HasPayload() override;

    static class Pimp* GetPimp();

protected:
    virtual void Checksum(const Packet&);

private:
    void Recv(uint8_t ctl, uint32_t len, uint32_t rseq, uint32_t rack);
    class TcpImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "tcp.h"
PROTOTOOL_NEW(TcpProtocol);
#endif

#endif

