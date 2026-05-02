//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2026 Charles R. Combs
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

#include <iostream>

#include "abc_io.h"
#include "cmd_parser.h"
#include "conf.h"
#include "data_parser.h"
#include "pcap_writer.h"
#include "stream_reader.h"

using namespace std;

int main (int argc, char* argv[]) {
    Conf c(argc, argv);

    if ( c.done )
        return 0;

    Reader* reader = new StreamReader;

    Parser* parser;
    if (c.raw)
        parser = new DataParser(reader);
    else
        parser = new CommandParser(reader, "a,b,c,d", c.trace_parser);

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
