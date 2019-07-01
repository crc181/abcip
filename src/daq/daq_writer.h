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
// daq writer stuff
//-------------------------------------------------------------------------

#ifndef __DAQ_WRITER_H__
#define __DAQ_WRITER_H__

#include <daq_common.h>

#include "writer.h"

class DaqWriter : public Writer {
public:
    DaqWriter(DAQ_ModuleInstance_h modinst, uint32_t pool_size, uint32_t snaplen, bool real_time);
    ~DaqWriter() override;

    void SetMsgVector(const DAQ_Msg_t* msgs[]);
    unsigned GetMsgCount();
    void ReleaseMsg(const DAQ_Msg_t* msg);
    void GetMsgPoolInfo(DAQ_MsgPoolInfo_t* info);

    void operator<<(const Packet&) override;

private:
    class DaqWriterImpl* impl;
};

#endif

