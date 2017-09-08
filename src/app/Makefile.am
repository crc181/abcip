
bin_PROGRAMS = abcip

abcip_SOURCES = \
main.cc \
pcap_writer.cc pcap_writer.h

abcip_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/common -I$(top_srcdir)/src/protos

abcip_LDADD = \
$(top_builddir)/src/protos/libproto.la \
$(top_builddir)/src/common/libcommon.la

