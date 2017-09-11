abcip is a simple packet crafting tool.  It is intended to be easy to generate
pcaps for testing, especially pcaps containing flawed packets.

To get started after cloning the repo, do this:

````
    ./bootstrap
    ./configure
    make
    make install
````

You can also ./configure --enable-daq to produce a DAQ that can be used with
Snort.  Use --with-daq-includes=/path/to/daq/include if needed.

To run it, do this:

abcip [options] < abc-file

Options are:
````
  --help or -? to get this help
  --help-a or -?a to get a list of a|b protocol options
  --help-b or -?b to get a list of a|b protocol options
  --help-c or -?c to get a list of c statement options
  --help-d or -?d to get a list of d statement options
  --help-bind to get a list of available protocol bindings
  --help-config same as --help-c
  --help-data to dump the default stream data
  --help-define same as --help-d
  --help-packet same as --help-a and --help-b
  --help-protos to get a list of supported protocols
  --help-users to get a list of supported users
  --license outputs license information
  --pcap <file> writes each packet to the given pcap file
  --raw changes input to just payload data (no commands)
  --snap <len=65535> set pcap snaplen
  --stack <protos=eth:ip4:tcp> sets default encapsulations
  --trace outputs a text summary of each packet
  --user <type=user> sets default user type
  --full-monty to use original scene V default stream data
  --full-dubya to use obfuscated scene V default stream data
  --version outputs version information
````
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

