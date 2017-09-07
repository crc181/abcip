AUTOMAKE_OPTIONS = foreign no-dependencies

AM_CXXFLAGS = -Wall -Wextra -Wformat -Wformat-security -pedantic

AM_CPPFLAGS = -I$(top_srcdir)/src/common

noinst_LTLIBRARIES = libproto.la

libproto_la_SOURCES = \
arp.cc arp.h \
eth.cc eth.h \
frag6.cc frag6.h \
gre.cc gre.h \
icmp4.cc icmp4.h \
icmp6.cc icmp6.h \
ip4.cc ip4.h \
ip6.cc ip6.h \
modbus.cc modbus.h \
mpls.cc mpls.h \
opt6.cc opt6.h \
phy.cc phy.h \
pimp.cc pimp.h \
ppp.cc ppp.h \
pppoe.cc pppoe.h \
protocol.cc protocol.h \
prototool.cc prototool.h \
raw.cc raw.h \
rte6.cc rte6.h \
tcp.cc tcp.h \
udp.cc udp.h \
vlan.cc vlan.h

BUILT_SOURCES = \
prototool-inc.h \
prototool-new.h

build_inc = \
    grep -h -A 2 "__PROTOTOOL_TAG__" $(top_srcdir)/src/protos/*.h | \
    sort -u | grep include | grep -iv xyz > prototool-inc.h;
 
build_new = \
    grep -h -A 2 "__PROTOTOOL_TAG__" $(top_srcdir)/src/protos/*.h | \
    sort -u | grep PROTOTOOL_NEW | grep -iv xyz > prototool-new.h;
 
prototool-inc.h: $(libproto_la_SOURCES)
	$(build_inc)

prototool-new.h: $(libproto_la_SOURCES)
	$(build_new)

clean-local:
	rm -f prototool-inc.h prototool-new.h
