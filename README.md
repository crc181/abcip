abcip is a simple packet crafting tool.  It is intended to be easy to generate
pcaps for testing, especially pcaps containing flawed packets.

To get started after cloning the repo, do this:

````
    autoreconf -isvf
    ./configure
    make
    make install
````

You can also ./configure --enable-daq to produce a DAQ that can be used with
Snort.  Use --with-daq-includes=/path/to/daq/include if needed.

To run it, do this:

abcip [options] < abc-file

Options are:

  --help or -? to get this help
  --help-types to get a list of supported hosts & protocols
  --help-bind to get a list of available protocol bindinds
  --help-define to get a list of d statement options
  --help-config to get a list of c statement options
  --help-fields to get a list of a|b statement options
  --help-data to dump the default stream data
  --host <type=co> to select host type
  --pcap <file> writes each packet to the given pcap file
  --snap <len=65535> set pcap snaplen
  --trace outputs a text summary of each packet
  --stack <protos=eth:ip4:tcp> sets protocols
  --version outputs version information
  --license outputs license information

abcip returns 0 for success or -1 for error reading abc file.
See the README for more information on the abc file.

Here is a an example abc file:

````
# define the stack
d ( stack="eth:ip4:tcp" )

# configure tcp ports
c ( 4:a=12345, b=80 )

# generate a packet from a to b
a ( syn )

# generate a packet from a to b
b ( syn, ack, len=16 )
````

This produces 2 packets: a syn from a to b and a syn-ack from b to a.  The
latter also has 16 bytes of payload.  The packets are both eth:ip4:tcp and
contain default values for anything not explicitly specified, such as
addresses.  The source port is 12345 and the destination port is 80.

