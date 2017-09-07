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

#include <stdio.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

extern "C" {
    #include <daq_common.h>
    #include <sfbpf_dlt.h>
};

#include "abc_daq.h"
#include "abc_io.h"
#include "cake.h"
#include "cmd_parser.h"
#include "daq_writer.h"
#include "data_parser.h"
#include "stream_reader.h"

//-------------------------------------------------------------------------

class AbcImpl {
public:
    bool LoadVars(const DAQ_Config_t*);

public:
    DAQ_Stats_t stats;
    DAQ_State state;

    int dlt;
    uint32_t snap;

    bool trace;
    bool raw;

    string stack;
    string user;

    char error[DAQ_ERRBUF_SIZE];

    AbcIo* abc;
    DaqWriter* writer;
};

bool AbcImpl::LoadVars (const DAQ_Config_t* cfg) {
    DAQ_Dict* entry;

    // defaults
    raw = false;
    trace = false;
    stack = DEFAULT_STACK;
    user = DEFAULT_USER;

    for ( entry = cfg->values; entry; entry = entry->next)
    {   
        if ( !strcmp(entry->key, "stack") )
            stack = entry->value;

        else if ( !strcmp(entry->key, "user") )
            user = entry->value;

        else if ( !strcmp(entry->key, "trace") )
            trace = true;

        else if ( !strcmp(entry->key, "raw") )
            raw = true;

        else
            break;
    }
    if ( entry )
        DPE(error, "ERROR: bad var (%s = %s)\n", entry->key, entry->value);

    return ( entry == NULL );
}

//-------------------------------------------------------------------------
//
static int GetDataLinkType (const char* proto) {
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
AbcDaq::AbcDaq (const DAQ_Config_t* cfg)
{
    impl = new AbcImpl;

    impl->LoadVars(cfg);

    impl->dlt = GetDataLinkType(impl->stack.c_str());
    impl->snap = cfg->snaplen;

    Reader* reader = new StreamReader(cfg->name);

    Parser* parser = impl->raw ?
        (Parser*)new DataParser(reader) :
        (Parser*)new CommandParser(reader, "a,b,c,d");

    impl->writer = new DaqWriter;

    impl->abc = new AbcIo(
        parser, impl->writer,
        impl->stack.c_str(), impl->user.c_str(),  impl->trace);

    ResetStats();

    impl->error[0] = '\0';
    impl->state = DAQ_STATE_INITIALIZED;
}

AbcDaq::~AbcDaq ()
{
    delete impl->abc;
}

//-------------------------------------------------------------------------
// packet processing functions:

int AbcDaq::Acquire (
    int cnt, DAQ_Analysis_Func_t callback, void* user)
{
    impl->writer->SetCallback(callback, user);
    int err = impl->abc->Execute(cnt);
    return (err < 0) ? err : DAQ_READFILE_EOF;
}

int AbcDaq::Inject (
    const DAQ_PktHdr_t* hdr, const uint8_t* data, uint32_t len, int reverse)
{
    return DAQ_ERROR_NOTSUP;
}

//-------------------------------------------------------------------------
// state stuff

int AbcDaq::Start ()
{
    impl->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

int AbcDaq::Stop ()
{
    impl->state = DAQ_STATE_STOPPED;
    return DAQ_SUCCESS;
}

int AbcDaq::Breakloop ()
{
    impl->abc->BreakLoop();
    return DAQ_SUCCESS;
}

//-------------------------------------------------------------------------
// accessors

DAQ_State AbcDaq::GetState ()
{
    return impl->state;
}

int AbcDaq::SetFilter (const char* filter)
{
    // TBD add bpf support
    return DAQ_ERROR_NOTSUP;
}

int AbcDaq::GetStats (DAQ_Stats_t* stats)
{
    impl->writer->GetStats(stats);
    return DAQ_SUCCESS;
}

void AbcDaq::ResetStats ()
{
    impl->writer->ResetStats();
}

int AbcDaq::GetSnaplen ()
{
    return impl->snap;
}

uint32_t AbcDaq::GetCapabilities ()
{
    uint32_t caps = DAQ_CAPA_BREAKLOOP /*| DAQ_CAPA_BPF*/;
    return caps;
}

int AbcDaq::GetDatalinkType ()
{
    return impl->dlt;
}

const char* AbcDaq::GetErrbuf ()
{
    return impl->error;
}

void AbcDaq::SetErrbuf (const char* s)
{
    DPE(impl->error, "%s", s ? s : "");
}

int AbcDaq::GetDeviceIndex (const char*)
{
    return DAQ_ERROR_NOTSUP;
}

