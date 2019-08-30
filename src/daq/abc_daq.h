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

#ifndef __ABC_DAQ_H__
#define __ABC_DAQ_H__

#include "base_daq.h"

class AbcDaq : public Daq {
public:
    AbcDaq(const DAQ_BaseAPI_t* base_api);
    ~AbcDaq() override;

    int Init(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst) override;

    int Start() override;
    int Interrupt() override;
    int Stop() override;

    int GetStats(DAQ_Stats_t*) override;
    void ResetStats() override;

    int GetSnaplen() override;
    uint32_t GetCapabilities() override;
    int GetDatalinkType() override;

    unsigned MsgReceive(const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rstat) override;
    int MsgFinalize(const DAQ_Msg_t* msg, DAQ_Verdict verdict) override;
    int GetMsgPoolInfo(DAQ_MsgPoolInfo_t* info) override;

private:
    class AbcImpl* impl;
};

#endif

