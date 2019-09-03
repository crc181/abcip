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

#include "abc_daq.h"

#include <daq_dlt.h>
#include <daq_module_api.h>

#include <cstring>

#include "abc_io.h"
#include "cmd_parser.h"
#include "daq_writer.h"
#include "data_parser.h"
#include "stream_reader.h"

using namespace std;

#define SET_ERROR(modinst, ...)    daq_base_api->set_errbuf(modinst, __VA_ARGS__)

#define ABC_DAQ_DEFAULT_POOL_SIZE 16

//-------------------------------------------------------------------------

class AbcImpl {
public:
    AbcImpl(const DAQ_BaseAPI_t* base_api) : daq_base_api(base_api) { }
    ~AbcImpl() { delete abc; }
    bool LoadVars(const DAQ_ModuleConfig_h modcfg);

public:
    const DAQ_BaseAPI_t* daq_base_api;
    DAQ_ModuleInstance_h modinst;

    DAQ_Stats_t stats;

    int dlt;
    uint32_t snap;

    bool trace = false;
    bool raw = false;
    bool real_time = false;
    bool interrupted = false;

    string stack = DEFAULT_STACK;
    string user = DEFAULT_USER;

    AbcIo* abc;
    DaqWriter* writer;
};

bool AbcImpl::LoadVars(const DAQ_ModuleConfig_h modcfg)
{
    const char* varKey, * varValue;
    daq_base_api->config_first_variable(modcfg, &varKey, &varValue);
    while (varKey)
    {
        if ( !strcmp(varKey, "stack") )
            stack = varValue;

        else if ( !strcmp(varKey, "user") )
            user = varValue;

        else if ( !strcmp(varKey, "trace") )
            trace = true;

        else if ( !strcmp(varKey, "raw") )
            raw = true;

        else if ( !strcmp(varKey, "real-time") )
            real_time = true;

        else
            break;
    }
    if ( varKey )
        SET_ERROR(modinst, "ERROR: bad var (%s = %s)\n", varKey, varValue);

    return ( varKey == nullptr );
}

//-------------------------------------------------------------------------
//
static int GetDataLinkType (const char* proto)
{
    if ( !strncasecmp(proto, "eth", 3) )
        return DLT_EN10MB;

    if ( !strncasecmp(proto, "ip4", 3) )
        return DLT_IPV4;

    if ( !strncasecmp(proto, "ip6", 3) )
        return DLT_IPV6;

    return DLT_RAW;
}

//-------------------------------------------------------------------------
// constructor / destructor
AbcDaq::AbcDaq(const DAQ_BaseAPI_t* base_api)
{
    impl = new AbcImpl(base_api);
}

int AbcDaq::Init(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst)
{
    impl->modinst = modinst;
    impl->LoadVars(modcfg);

    impl->dlt = GetDataLinkType(impl->stack.c_str());
    impl->snap = impl->daq_base_api->config_get_snaplen(modcfg);

    Reader* reader = new StreamReader(impl->daq_base_api->config_get_input(modcfg));

    Parser* parser;
    if (impl->raw)
        parser = new DataParser(reader);
    else
        parser = new CommandParser(reader, "a,b,c,d");

    uint32_t pool_size = impl->daq_base_api->config_get_msg_pool_size(modcfg);
    if (pool_size == 0)
        pool_size = ABC_DAQ_DEFAULT_POOL_SIZE;
    impl->writer = new DaqWriter(modinst, pool_size, impl->snap, impl->real_time);

    impl->abc = new AbcIo(
        parser, impl->writer,
        impl->stack.c_str(), impl->user.c_str(),  impl->trace);

    ResetStats();

    return DAQ_SUCCESS;
}

AbcDaq::~AbcDaq ()
{
    delete impl;
}

//-------------------------------------------------------------------------
// packet processing functions:

unsigned AbcDaq::MsgReceive(const unsigned max_recv, const DAQ_Msg_t* msgs[], DAQ_RecvStatus* rstat)
{
    impl->writer->SetMsgVector(msgs);
    int err = impl->abc->Execute(max_recv);
    unsigned num_receive = impl->writer->GetMsgCount();
    impl->stats.packets_received += num_receive;
    if (err < 0)
       *rstat = DAQ_RSTAT_ERROR;
    else if (err == 0 || num_receive < max_recv)
    {
        if (impl->interrupted)
        {
            impl->interrupted = false;
            *rstat = DAQ_RSTAT_INTERRUPTED;
        }
        else
            *rstat = DAQ_RSTAT_EOF;
    }
    else
        *rstat = DAQ_RSTAT_OK;

    return num_receive;
}

int AbcDaq::MsgFinalize(const DAQ_Msg_t* msg, DAQ_Verdict verdict)
{
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    impl->stats.verdicts[verdict]++;
    impl->writer->ReleaseMsg(msg);

    return DAQ_SUCCESS;
}

int AbcDaq::GetMsgPoolInfo(DAQ_MsgPoolInfo_t* info)
{
    impl->writer->GetMsgPoolInfo(info);
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// state stuff

int AbcDaq::Start ()
{
    return DAQ_SUCCESS;
}

int AbcDaq::Stop ()
{
    return DAQ_SUCCESS;
}

int AbcDaq::Interrupt ()
{
    impl->abc->Interrupt();
    impl->interrupted = true;
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// accessors

int AbcDaq::GetStats (DAQ_Stats_t* stats)
{
    *stats = impl->stats;
    return DAQ_SUCCESS;
}

void AbcDaq::ResetStats ()
{
    memset(&impl->stats, 0, sizeof(impl->stats));
}

int AbcDaq::GetSnaplen ()
{
    return impl->snap;
}

uint32_t AbcDaq::GetCapabilities ()
{
    uint32_t caps = DAQ_CAPA_REPLACE | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_INTERRUPT;
    return caps;
}

int AbcDaq::GetDatalinkType ()
{
    return impl->dlt;
}

