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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

extern "C" {
    #include <daq_api.h>
    #include <sfbpf_dlt.h>
};

#include "daq_lib.h"
#include "base_daq.h"

//-------------------------------------------------------------------------
// ctor / dtor 

static int daq_initialize (
    const DAQ_Config_t* cfg, void** handle, char* errBuf, size_t errMax)
{
    Daq* daq = new DAQ_CLASS(cfg);

    // FIXTHIS use try / catch
    if ( !daq )
    {
        snprintf(errBuf, errMax,
            "%s: Couldn't instantiate the DAQ",
            __FUNCTION__);
        return DAQ_ERROR_NOMEM;
    }
    *handle = daq;

    return DAQ_SUCCESS;
}

static void daq_shutdown (void* handle)
{
    Daq* daq = (Daq*)handle;
    delete daq;
}

//-------------------------------------------------------------------------
// standard bindings

static int daq_acquire (
    void* handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t, void* user)
{
    Daq* daq = (Daq*)handle;
    return daq->Acquire(cnt, callback, user);
}

static int daq_inject (
    void* handle, const DAQ_PktHdr_t* hdr, const uint8_t* data, uint32_t len,
    int reverse)
{
    Daq* daq = (Daq*)handle;
    return daq->Inject(hdr, data, len, reverse);
}

static int daq_start (void* handle)
{
    Daq* daq = (Daq*)handle;
    return daq->Start();
}

static int daq_stop (void* handle)
{
    Daq* daq = (Daq*)handle;
    return daq->Stop();
}

static int daq_breakloop (void* handle)
{
    Daq* daq = (Daq*)handle;
    return daq->Breakloop();
}

static DAQ_State daq_check_status (void* handle)
{
    Daq* daq = (Daq*)handle;
    return daq->GetState();
}

static int daq_set_filter (void* handle, const char* filter)
{
    Daq* daq = (Daq*)handle;
    return daq->SetFilter(filter);
}

static int daq_get_stats (void* handle, DAQ_Stats_t* stats)
{
    Daq* daq = (Daq*)handle;
    return daq->GetStats(stats);
}

static void daq_reset_stats (void* handle)
{
    Daq* daq = (Daq*)handle;
    daq->ResetStats();
}

static int daq_get_snaplen (void* handle)
{
    Daq* daq = (Daq*)handle;
    return daq->GetSnaplen();
}

static uint32_t daq_get_capabilities (void* handle)
{
    Daq* daq = (Daq*)handle;
    return daq->GetCapabilities();
}

static int daq_get_datalink_type (void *handle)
{
    Daq* daq = (Daq*)handle;
    return daq->GetDatalinkType();
}

static const char* daq_get_errbuf (void* handle)
{
    Daq* daq = (Daq*)handle;
    return daq->GetErrbuf();
}

static void daq_set_errbuf (void* handle, const char* s)
{
    Daq* daq = (Daq*)handle;
    return daq->SetErrbuf(s);
}

static int daq_get_device_index(void* handle, const char* device)
{
    Daq* daq = (Daq*)handle;
    return daq->GetDeviceIndex(device);
}

//-------------------------------------------------------------------------

extern "C" {
  DAQ_Module_t DAQ_MODULE_DATA = 
  {
    /*.api_version =*/ DAQ_API_VERSION,
    /*.module_version =*/ DAQ_VER,
    /*.name =*/ DAQ_NAME,
    /*.type =*/ DAQ_TYPE,
    /*.initialize =*/ daq_initialize,
    /*.set_filter =*/ daq_set_filter,
    /*.start =*/ daq_start,
    /*.acquire =*/ daq_acquire,
    /*.inject =*/ daq_inject,
    /*.breakloop =*/ daq_breakloop,
    /*.stop =*/ daq_stop,
    /*.shutdown =*/ daq_shutdown,
    /*.check_status =*/ daq_check_status,
    /*.get_stats =*/ daq_get_stats,
    /*.reset_stats =*/ daq_reset_stats,
    /*.get_snaplen =*/ daq_get_snaplen,
    /*.get_capabilities =*/ daq_get_capabilities,
    /*.get_datalink_type =*/ daq_get_datalink_type,
    /*.get_errbuf =*/ daq_get_errbuf,
    /*.set_errbuf =*/ daq_set_errbuf,
    /*.get_device_index =*/ daq_get_device_index,
    NULL,
    NULL,
    NULL,
    NULL
  };
};

