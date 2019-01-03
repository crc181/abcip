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

#ifndef __BASE_DAQ_H__
#define __BASE_DAQ_H__

#include <daq_module_api.h>

class Daq {
public:
    virtual ~Daq() { };

    virtual int Init(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst) = 0;

    virtual int SetFilter(const char* filter);

    virtual int Start();
    virtual int Inject(DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len);
    virtual int InjectRelative(const DAQ_Msg_t* msg, const uint8_t* data, uint32_t data_len, int reverse);
    virtual int Interrupt();
    virtual int Stop();
    virtual int Ioctl(DAQ_IoctlCmd cmd, void* arg, size_t arglen);

    virtual int GetStats(DAQ_Stats_t*);
    virtual void ResetStats();

    virtual int GetSnaplen();
    virtual uint32_t GetCapabilities();
    virtual int GetDatalinkType();

    virtual unsigned MsgReceive(const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rstat);
    virtual int MsgFinalize(const DAQ_Msg_t* msg, DAQ_Verdict verdict);
    virtual int GetMsgPoolInfo(DAQ_MsgPoolInfo_t* info);

protected:
    Daq() { };
};

#endif

