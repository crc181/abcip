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
