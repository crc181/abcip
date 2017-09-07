AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = daq_abc.la

daq_abc_la_SOURCES = \
abc_daq.h abc_daq.cc \
base_daq.h \
daq_lib.h daq_lib.cc \
daq_writer.h daq_writer.cc

daq_abc_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
daq_abc_la_LIBADD = \
-lpcap \
$(top_builddir)/src/protos/libproto.la \
$(top_builddir)/src/common/libcommon.la

AM_CPPFLAGS = -I$(top_srcdir)/src/common -I$(top_srcdir)/src/protos
