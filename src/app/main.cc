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
// abcip stuff
//-------------------------------------------------------------------------
// the goal is a simple way to generate packets with various
// encapsulations.
//
// it will use defaults that create a valid session but can be 
// overridden as needed to create a flawed session.
//
// the emphasis here is on flexibility and correctness (ie
// producing pcaps as defined in the abc file, which may exhibit
// protocol errors).  no sacrifices made for gigabit performance.
// and errors, like setting random variables, are silently
// ignored.
//
// the code at least tries to make it easy to add new users and
// protocols.  just clone/modify a user or protocol and then
// add it to the factory methods in user.cc or include the
// special foo in your protocol .h (and add the modules to
// Makefile.am).
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>
#include <cstring>
#include <iostream>

#include "abc_io.h"
#include "abc_ip.h"
#include "cmd_parser.h"
#include "command.h"
#include "data.h"
#include "data_parser.h"
#include "pcap_writer.h"
#include "protocol.h"
#include "prototool.h"
#include "stream_reader.h"

using namespace std;

//-------------------------------------------------------------------------

static const char* usage =
"abcip [options] < abc-file\n"
"\n"
"Options are:\n"
"\n"
"  --help or -? to get this help\n"
"  --help-a or -?a to get a list of a|b protocol options\n"
"  --help-b or -?b to get a list of a|b protocol options\n"
"  --help-c or -?c to get a list of c statement options\n"
"  --help-d or -?d to get a list of d statement options\n"
"  --help-bind to get a list of available protocol bindings\n"
"  --help-config same as --help-c\n"
"  --help-data to dump the default stream data\n"
"  --help-define same as --help-d\n"
"  --help-packet same as --help-a and --help-b\n"
"  --help-protos to get a list of supported protocols\n"
"  --help-users to get a list of supported users\n"
"  --license outputs license information\n"
"  --pcap <file> writes each packet to the given pcap file\n"
"  --raw changes input to just payload data (no commands)\n"
"  --snap <len=65535> set pcap snaplen\n"
"  --stack <protos=" DEFAULT_STACK "> sets default encapsulations\n"
"  --trace outputs a text summary of each packet\n"
"  --user <type=" DEFAULT_USER "> sets default user type\n"
"  --full-monty to use original scene V default stream data\n"
"  --full-dubya to use obfuscated scene V default stream data\n"
"  --version outputs version information\n"
"\n"
"abcip returns 0 for success or -1 for error reading abc file.\n"
"See the README for more information on the abc file.\n"
;

static const char* version =
"package:  " PACKAGE_NAME "\n"
"version:  " PACKAGE_VERSION "\n"
"bugs to:  " PACKAGE_BUGREPORT "\n";

static const char* license =
"abcip is Copyright (C) 2010-2017 Charles R. Combs" "\n"
"Released under GNU General Public License version 3" "\n"
"See http://www.gnu.org/licenses/gpl.txt"
" for license, copying, and warranty information." "\n";

//-------------------------------------------------------------------------

class Conf {
public:
    Conf(int argc, char* argv[]);

public:
    const char* pcap;
    const char* stack;
    const char* user;
    uint16_t snap;
    bool trace, raw;
};

Conf::Conf (int argc, char* argv[]) {
    pcap = nullptr;
    snap = 65535;
    trace = raw = false;
    stack = DEFAULT_STACK;
    user = DEFAULT_USER;

    for ( int i = 1; i < argc; i++ ) {
        if ( !strcasecmp(argv[i], "--pcap") && (i+1 < argc) ) {
            pcap = argv[++i];
        }
        else if ( !strcasecmp(argv[i], "--snap") && (i+1 < argc) ) {
            snap = atoi(argv[++i]);
        }
        else if ( !strcasecmp(argv[i], "--stack") && (i+1 < argc) ) {
            stack = argv[++i];
        }
        else if ( !strcasecmp(argv[i], "--trace") ) {
            trace = true;
        }
        else if ( !strcasecmp(argv[i], "--raw") ) {
            raw = true;
        }
        else if ( !strcasecmp(argv[i], "--user") ) {
            user = argv[++i];
        }
        else if ( !strcasecmp(argv[i], "--full-monty") ) {
            SetData(DATA_FULL_MONTY);
        }
        else if ( !strcasecmp(argv[i], "--full-dubya") ) {
            SetData(DATA_FULL_DUBYA);
        }
        else if ( !strcasecmp(argv[i], "--help")
               || !strcmp(argv[i], "-?") ) {
            cout << usage;
            exit(0);
        }
        else if ( !strcasecmp(argv[i], "--help-users") ) {
            User::HelpTypes(cout);
            exit(0);
        }
        else if ( !strcasecmp(argv[i], "--help-protos") ) {
            ProtoTool::HelpTypes(cout);
            exit(0);
        }
        else if ( !strcasecmp(argv[i], "--help-bind") ) {
            ProtoTool::HelpBind(cout);
            exit(0);
        }
        else if (
            !strcasecmp(argv[i], "-?a") ||
            !strcasecmp(argv[i], "-?b") ||
            !strcasecmp(argv[i], "--help-a") ||
            !strcasecmp(argv[i], "--help-b") ||
            !strcasecmp(argv[i], "--help-packet")
        ) {
            User::HelpPacket(cout);
            ProtoTool::HelpPacket(cout);
            exit(0);
        }
        else if (
            !strcasecmp(argv[i], "-?c") ||
            !strcasecmp(argv[i], "--help-c") ||
            !strcasecmp(argv[i], "--help-config")
        ) {
            User::HelpConfig(cout);
            ProtoTool::HelpConfig(cout);
            exit(0);
        }
        else if (
            !strcasecmp(argv[i], "-?d") ||
            !strcasecmp(argv[i], "--help-d") ||
            !strcasecmp(argv[i], "--help-define")
        ) {
            AbcIo::HelpDefine(cout);
            exit(0);
        }
        else if ( !strcasecmp(argv[i], "--help-data") ) {
            cout << GetData();
            exit(0);
        }
        else if ( !strcasecmp(argv[i], "--version") ) {
            cout << version;
            exit(0);
        }
        else if ( !strcasecmp(argv[i], "--license") ) {
            cout << license;
            exit(0);
        }
        else {
            cerr << "Unknown option: " << argv[i] << endl;
            exit(-1);
       }
    }
}

//-------------------------------------------------------------------------

int main (int argc, char* argv[]) {
    Conf c(argc, argv);

    Reader* reader = new StreamReader;

    Parser* parser;
    if (c.raw)
        parser = new DataParser(reader);
    else
        parser = new CommandParser(reader, "a,b,c,d");

    Writer* writer = c.pcap ? 
        new PcapWriter(c.pcap, c.stack, c.snap) : nullptr;

    AbcIo abc(parser, writer, c.stack, c.user, c.trace);

    if ( writer && !writer->Ok() )
        return -1;

    int numCmds = abc.Execute(-1);

    if ( numCmds < 0 )
        return numCmds;

    cout << numCmds << " commands processed" << endl;
    return 0;
}

