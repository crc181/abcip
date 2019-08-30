//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2018-2019 Charles R. Combs
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "base_daq.h"

#include <daq_dlt.h>

int Daq::SetFilter(const char*) { return DAQ_ERROR_NOTSUP; }

int Daq::Start() { return DAQ_SUCCESS; }
int Daq::Inject(DAQ_MsgType, const void*, const uint8_t*, uint32_t) { return DAQ_ERROR_NOTSUP; }
int Daq::InjectRelative(const DAQ_Msg_t*, const uint8_t*, uint32_t, int) { return DAQ_ERROR_NOTSUP; }
int Daq::Interrupt() { return DAQ_ERROR_NOTSUP; }
int Daq::Stop() { return DAQ_SUCCESS; }
int Daq::Ioctl(DAQ_IoctlCmd, void*, size_t) { return DAQ_ERROR_NOTSUP; }

int Daq::GetStats(DAQ_Stats_t*) { return DAQ_ERROR_NOTSUP; }
void Daq::ResetStats() { }

int Daq::GetSnaplen() { return -1; }
uint32_t Daq::GetCapabilities() { return 0; }
int Daq::GetDatalinkType() { return DLT_NULL; }

unsigned Daq::MsgReceive(const unsigned, const DAQ_Msg_t**, DAQ_RecvStatus*) { return DAQ_ERROR_NOTSUP; }
int Daq::MsgFinalize(const DAQ_Msg_t*, DAQ_Verdict) { return DAQ_ERROR_NOTSUP; }
int Daq::GetMsgPoolInfo(DAQ_MsgPoolInfo_t*) { return DAQ_ERROR_NOTSUP; }
