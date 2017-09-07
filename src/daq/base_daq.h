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

#ifndef __BASE_DAQ_H__
#define __BASE_DAQ_H__

extern "C" {
    #include <daq_common.h>
    #include <daq_api.h>
};

class Daq {
public:
    virtual ~Daq() { };

    virtual int Acquire(int cnt, DAQ_Analysis_Func_t, void* user) = 0;
    virtual int Inject(
        const DAQ_PktHdr_t*, const uint8_t* data, uint32_t len, int reverse) = 0;

    virtual int Start() = 0;
    virtual int Stop() = 0;
    virtual int Breakloop() = 0;

    virtual uint32_t GetCapabilities() = 0;
    virtual DAQ_State GetState() = 0;
    virtual int SetFilter(const char* filter) = 0;

    virtual int GetStats(DAQ_Stats_t*) = 0;
    virtual void ResetStats() = 0;

    virtual int GetSnaplen() = 0;
    virtual int GetDatalinkType() = 0;
    virtual int GetDeviceIndex(const char* device) = 0;

    virtual const char* GetErrbuf() = 0;
    virtual void SetErrbuf(const char* s) = 0;

protected:
    Daq() { };
};

#endif

