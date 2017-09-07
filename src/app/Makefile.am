AUTOMAKE_OPTIONS = foreign no-dependencies
AM_CXXFLAGS = -Wall -Wextra -Wformat -Wformat-security -pedantic

bin_PROGRAMS = abcip

abcip_SOURCES = \
main.cc \
pcap_writer.cc pcap_writer.h

abcip_LDADD = \
$(top_builddir)/src/protos/libproto.la \
$(top_builddir)/src/common/libcommon.la

AM_CPPFLAGS = -I$(top_srcdir)/src/common -I$(top_srcdir)/src/protos

