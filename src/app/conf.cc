#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "conf.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

#include "abc_io.h"
#include "data.h"
#include "prototool.h"
#include "stream_reader.h"
#include "user.h"

using namespace std;

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
"  --trace-parser outputs lexer and parser state transitions\n"
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

std::ostream& Conf::get_cout() { return std::cout; }

Conf::Conf(int argc, char* argv[], ostream& out) {
    pcap = nullptr;
    snap = 65535;
    trace = trace_parser = raw = done = false;
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
        else if ( !strcasecmp(argv[i], "--trace-parser") ) {
            trace_parser = true;
        }
        else if ( !strcasecmp(argv[i], "--raw") ) {
            raw = true;
        }
        else if ( !strcasecmp(argv[i], "--user") && (i+1 < argc) ) {
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
            out << usage;
            done = true; return;
        }
        else if ( !strcasecmp(argv[i], "--help-users") ) {
            User::HelpTypes(out);
            done = true; return;
        }
        else if ( !strcasecmp(argv[i], "--help-protos") ) {
            ProtoTool::HelpTypes(out);
            done = true; return;
        }
        else if ( !strcasecmp(argv[i], "--help-bind") ) {
            ProtoTool::HelpBind(out);
            done = true; return;
        }
        else if (
            !strcasecmp(argv[i], "-?a") ||
            !strcasecmp(argv[i], "-?b") ||
            !strcasecmp(argv[i], "--help-a") ||
            !strcasecmp(argv[i], "--help-b") ||
            !strcasecmp(argv[i], "--help-packet")
        ) {
            User::HelpPacket(out);
            ProtoTool::HelpPacket(out);
            done = true; return;
        }
        else if (
            !strcasecmp(argv[i], "-?c") ||
            !strcasecmp(argv[i], "--help-c") ||
            !strcasecmp(argv[i], "--help-config")
        ) {
            User::HelpConfig(out);
            ProtoTool::HelpConfig(out);
            done = true; return;
        }
        else if (
            !strcasecmp(argv[i], "-?d") ||
            !strcasecmp(argv[i], "--help-d") ||
            !strcasecmp(argv[i], "--help-define")
        ) {
            AbcIo::HelpDefine(out);
            done = true; return;
        }
        else if ( !strcasecmp(argv[i], "--help-data") ) {
            out << GetData();
            done = true; return;
        }
        else if ( !strcasecmp(argv[i], "--version") ) {
            out << version;
            done = true; return;
        }
        else if ( !strcasecmp(argv[i], "--license") ) {
            out << license;
            done = true; return;
        }
        else {
            out << "Unknown option: " << argv[i] << "\n";
            done = true; return;
        }
    }
}
