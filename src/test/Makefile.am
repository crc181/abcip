AM_CPPFLAGS = \
    $(CATCH2_CPPFLAGS) \
    $(LIBDAQ_CFLAGS) \
    -I$(top_srcdir)/src/common \
    -I$(top_srcdir)/src/protos \
    -I$(top_srcdir)/src/daq \
    -I$(top_srcdir)/src/app

AM_CXXFLAGS = $(CATCH2_CXXFLAGS) -Wno-c++17-extensions

AM_LDFLAGS  = -L$(top_builddir)/src/common -L$(top_builddir)/src/protos
LDADD       = \
    $(top_builddir)/src/protos/libproto.la \
    $(top_builddir)/src/common/libcommon.la \
    $(CATCH2_LIBS) \
    -lpcap

check_PROGRAMS = \
    attribute_test \
    cake_test \
    tcp_test \
    ip4_test \
    geneve_test \
    cisco_metadata_test \
    phy_test \
    prototool_test \
    raw_test \
    data_parser_test \
    daq_test \
    conf_test \
    abc_io_test

attribute_test_SOURCES       = attribute_test.cc
cake_test_SOURCES            = cake_test.cc
tcp_test_SOURCES             = tcp_test.cc
ip4_test_SOURCES             = ip4_test.cc
geneve_test_SOURCES          = geneve_test.cc
cisco_metadata_test_SOURCES  = cisco_metadata_test.cc
phy_test_SOURCES             = phy_test.cc
prototool_test_SOURCES       = prototool_test.cc
raw_test_SOURCES             = raw_test.cc
data_parser_test_SOURCES     = data_parser_test.cc
conf_test_SOURCES            = conf_test.cc $(top_srcdir)/src/app/conf.cc
conf_test_CXXFLAGS           = $(AM_CXXFLAGS) -I$(top_srcdir)/src/app
conf_test_LDADD              = \
    $(top_builddir)/src/protos/libproto.la \
    $(top_builddir)/src/common/libcommon.la \
    $(CATCH2_LIBS) \
    -lpcap

abc_io_test_SOURCES          = abc_io_test.cc
abc_io_test_LDADD            = \
    $(top_builddir)/src/protos/libproto.la \
    $(top_builddir)/src/common/libcommon.la \
    $(CATCH2_LIBS) \
    -lpcap

daq_test_CXXFLAGS            = \
    $(AM_CXXFLAGS) \
    -DARP_ABC=\"$(top_srcdir)/test/arp.abc\" \
    -DARP_REF=\"$(top_srcdir)/test/ref/arp.pcap\"
daq_test_SOURCES             = daq_test.cc
daq_test_LDADD               = \
    $(top_builddir)/src/daq/.libs/daq_abc_la-abc_daq.o \
    $(top_builddir)/src/daq/.libs/daq_abc_la-base_daq.o \
    $(top_builddir)/src/daq/.libs/daq_abc_la-daq_lib.o \
    $(top_builddir)/src/daq/.libs/daq_abc_la-daq_writer.o \
    $(top_builddir)/src/protos/libproto.la \
    $(top_builddir)/src/common/libcommon.la \
    $(CATCH2_LIBS) \
    -lpcap
daq_test_LDFLAGS             = \
    -L$(top_builddir)/src/common \
    -L$(top_builddir)/src/protos

TESTS = $(check_PROGRAMS)
