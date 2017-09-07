#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([abcip], [2.2.1], [crc181@gmail.com])

AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_GREP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_lib_version],,AC_ERROR([Missing libpcap >= 1.0.0]))

# Checks for host.
case "$host" in
    *darwin*)
    AC_DEFINE([MACOSX], [1], [Define if MacOSX])
    ;;
    *-linux*)
    AC_DEFINE([LINUX], [1], [Define if Linux])
    ;;
esac

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h string.h daq_api.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

AC_HEADER_STDBOOL
AC_HEADER_TIME

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

AC_ENABLE_VISIBILITY()

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset strcasecmp strncasecmp strtol])

# abc daq
AC_ARG_ENABLE([daq],
    AC_HELP_STRING([--enable-daq],[build the abc daq module]),
    [enable_daq=$enableval], [enable_daq=no])

AM_CONDITIONAL([BUILD_DAQ], [test "x$enable_daq" = xyes])

# FIXTHIS make conditional on enable_daq or with_daq_includes
# should enable_daq; also should only add daq includes to daq
# makes
# Checks for libraries.
AC_ARG_WITH([daq_includes],
    [  --with-daq-includes=DIR    libdaq include directory],
    [with_daq_includes="$withval"], [with_daq_includes="no"])

if test "x$with_daq_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_daq_includes}"
    SOURCE="${with_daq_includes}"
fi

AC_CONFIG_FILES([ \
    Makefile \
    src/Makefile \
    src/common/Makefile \
    src/protos/Makefile \
    src/app/Makefile \
    src/daq/Makefile \
    doc/Makefile \
    test/Makefile \
])

AC_OUTPUT
