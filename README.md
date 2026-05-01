abcip is a simple packet crafting tool.  It is intended to be easy to generate
pcaps for testing, especially pcaps containing flawed packets.

To get started after cloning the repo, do this:

````
    ./bootstrap
    ./configure --enable-unit-tests
    make
    make install
````

To also build the DAQ module (for use with Snort), libdaq must be available via
pkg-config.  Set PKG_CONFIG_PATH if needed and add --enable-daq:

````
    PKG_CONFIG_PATH=/path/to/daq/install/lib/pkgconfig \
    ./configure --enable-unit-tests --enable-daq
````

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

# generate a packet from b to a
b ( syn, ack, len=16 )
````

This produces 2 packets: a syn from a to b and a syn-ack from b to a.  The
latter also has 16 bytes of payload.  The packets are both eth:ip4:tcp and
contain default values for anything not explicitly specified, such as
addresses.  The source port is 12345 and the destination port is 80.

Supported protocols are:
````
  arp                 ARP
  cisco               Cisco Metadata (ethertype 0x8909)
  dst6                IPv6 destination options extension header
  eth                 Ethernet
  frag6               IPv6 fragment extension header
  geneve              Geneve tunnel (RFC 8926)
  gre                 GRE tunnel
  hop6                IPv6 hop-by-hop options extension header
  icmp4               ICMPv4
  icmp6               ICMPv6
  ip4                 IPv4
  ip6                 IPv6
  modbus              Modbus/TCP
  mpls                MPLS
  phy                 Physical layer (auto-added as bottom layer)
  ppp                 PPP
  pppoe               PPPoE
  raw                 Raw payload (no header)
  rte6                IPv6 routing extension header
  tcp                 TCP
  udp                 UDP
  vlan                802.1Q VLAN
````
