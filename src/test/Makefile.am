AM_CPPFLAGS = \
    $(CATCH2_CPPFLAGS) \
    -I$(top_srcdir)/src/common \
    -I$(top_srcdir)/src/protos

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
    phy_test

attribute_test_SOURCES       = attribute_test.cc
cake_test_SOURCES            = cake_test.cc
tcp_test_SOURCES             = tcp_test.cc
ip4_test_SOURCES             = ip4_test.cc
geneve_test_SOURCES          = geneve_test.cc
cisco_metadata_test_SOURCES  = cisco_metadata_test.cc
phy_test_SOURCES             = phy_test.cc

TESTS = $(check_PROGRAMS)
