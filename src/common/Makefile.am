AUTOMAKE_OPTIONS = foreign no-dependencies
AM_CXXFLAGS = -Wall -Wextra -Wformat -Wformat-security -pedantic

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = \
abc_io.cc abc_io.h \
abc_ip.cc abc_ip.h \
attribute.cc attribute.h \
cake.cc cake.h \
cmd_parser.cc cmd_parser.h \
command.h \
data.cc data.h \
data_parser.cc data_parser.h \
dumb_user.cc dumb_user.h \
field.cc field.h \
packet.h \
parser.h \
pile.cc pile.h \
pseudo_hdr.h pseudo_hdr.cc \
reader.h \
status.cc status.h \
stream_reader.cc stream_reader.h \
user.cc user.h \
writer.h

AM_CPPFLAGS = -I$(top_srcdir)/src/protos

