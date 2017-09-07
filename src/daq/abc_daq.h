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

#ifndef __ABC_DAQ_H__
#define __ABC_DAQ_H__

#include "base_daq.h"

class AbcDaq : public Daq {
public:
    AbcDaq(const DAQ_Config_t*);
    ~AbcDaq();

    int Acquire(int cnt, DAQ_Analysis_Func_t, void* user);
    int Inject(const DAQ_PktHdr_t*, const uint8_t* data, uint32_t len, int reverse);

    int Start();
    int Stop();
    int Breakloop();

    uint32_t GetCapabilities();
    DAQ_State GetState();
    int SetFilter(const char* filter);

    int GetStats(DAQ_Stats_t* stats);
    void ResetStats();

    int GetSnaplen();
    int GetDatalinkType();
    int GetDeviceIndex(const char* device);

    const char* GetErrbuf();
    void SetErrbuf(const char* s);

private:
    class AbcImpl* impl;
};

#endif

