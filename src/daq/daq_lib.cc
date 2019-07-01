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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "daq_lib.h"

#include <daq_module_api.h>

#include <cstring>

#include "base_daq.h"

static DAQ_BaseAPI_t daq_base_api;


static int daq_module_load(const DAQ_BaseAPI_t* base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;

    return DAQ_SUCCESS;
}

static int daq_module_unload()
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int daq_get_variable_descs(const DAQ_VariableDesc_t** var_desc_table)
{
    *var_desc_table = nullptr;

    return 0;
}

//-------------------------------------------------------------------------
// ctor / dtor 

static int daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void** ctxt_ptr)
{
    Daq* daq = new DAQ_CLASS(&daq_base_api);
    int rval = daq->Init(modcfg, modinst);
    if (rval != DAQ_SUCCESS)
    {
        delete daq;
        return rval;
    }

    *ctxt_ptr = daq;

    return DAQ_SUCCESS;
}

static void daq_destroy(void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    delete daq;
}

//-------------------------------------------------------------------------
// standard bindings

static int daq_set_filter (void* handle, const char* filter)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->SetFilter(filter);
}

static int daq_start (void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->Start();
}

static int daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->Inject(type, hdr, data, data_len);
}

static int daq_inject_relative(void* handle, const DAQ_Msg_t* msg, const uint8_t* data,
        uint32_t data_len, int reverse)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->InjectRelative(msg, data, data_len, reverse);
}

static int daq_interrupt(void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->Interrupt();
}

static int daq_stop (void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->Stop();
}

static int daq_ioctl(void* handle, DAQ_IoctlCmd cmd, void* arg, size_t arglen)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->Ioctl(cmd, arg, arglen);
}

static int daq_get_stats (void* handle, DAQ_Stats_t* stats)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->GetStats(stats);
}

static void daq_reset_stats (void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    daq->ResetStats();
}

static int daq_get_snaplen (void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->GetSnaplen();
}

static uint32_t daq_get_capabilities (void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->GetCapabilities();
}

static int daq_get_datalink_type (void* handle)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->GetDatalinkType();
}

static unsigned daq_msg_receive(void* handle, const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rstat)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->MsgReceive(max_recv, msgs, rstat);
}

static int daq_msg_finalize(void* handle, const DAQ_Msg_t* msg, DAQ_Verdict verdict)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->MsgFinalize(msg, verdict);
}

static int daq_get_msg_pool_info(void* handle, DAQ_MsgPoolInfo_t* info)
{
    Daq* daq = static_cast<Daq*>(handle);
    return daq->GetMsgPoolInfo(info);
}

//-------------------------------------------------------------------------

extern "C" {
  DAQ_SO_PUBLIC DAQ_ModuleAPI_t DAQ_MODULE_DATA =
  {
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_VER,
    /* .name = */ DAQ_NAME,
    /* .type = */ DAQ_TYPE,
    /* .load = */ daq_module_load,
    /* .unload = */ daq_module_unload,
    /* .get_variable_descs = */ daq_get_variable_descs,
    /* .instantiate = */ daq_instantiate,
    /* .destroy = */ daq_destroy,
    /* .set_filter = */ daq_set_filter,
    /* .start = */ daq_start,
    /* .inject = */ daq_inject,
    /* .inject = */ daq_inject_relative,
    /* .interrupt = */ daq_interrupt,
    /* .stop = */ daq_stop,
    /* .ioctl = */ daq_ioctl,
    /* .get_stats = */ daq_get_stats,
    /* .reset_stats = */ daq_reset_stats,
    /* .get_snaplen = */ daq_get_snaplen,
    /* .get_capabilities = */ daq_get_capabilities,
    /* .get_datalink_type = */ daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ daq_msg_receive,
    /* .msg_finalize = */ daq_msg_finalize,
    /* .get_msg_pool_info = */ daq_get_msg_pool_info,
  };
}

