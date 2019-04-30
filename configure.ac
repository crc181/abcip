#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([abcip],
        m4_esyscmd([build-aux/git-version-gen .tarball-version]),
        [crc181@gmail.com])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall -Wno-extra-portability -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_GREP
AC_PROG_INSTALL
LT_INIT

# Set default language to C++
AC_LANG([C++])
AX_CXX_COMPILE_STDCXX_11

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_lib_version],,AC_MSG_ERROR(Missing libpcap >= 1.0.0))

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
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

AC_HEADER_STDBOOL
AC_HEADER_TIME

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Visibility foo (enable it if we can)
gl_VISIBILITY()
CPPFLAGS="$CFLAG_VISIBILITY $CPPFLAGS"

# Checks for library functions.
AC_CHECK_FUNCS([gettimeofday memset strcasecmp strncasecmp strtol])

# abc daq
AC_ARG_ENABLE([daq],
    AS_HELP_STRING([--disable-daq],[disable building with libdaq support (including the abcip DAQ module)]))

if test "x$enable_daq" != "xno" ; then
    # Checks for the LibDAQ headers.
    AC_CHECK_DAQ_HEADERS
    if test "x$HAVE_DAQ_HEADERS" != "xyes"; then
        AC_MSG_ERROR([Could not find LibDAQ headers!])
    fi

    AC_DEFINE([HAVE_DAQ],[1],[can build DAQ code])
fi

AM_CONDITIONAL([BUILD_DAQ], [test "x$enable_daq" != xno])

AM_CPPFLAGS="-Wall -Wextra -Wformat -Wformat-security -pedantic ${LIBDAQ_CPPFLAGS}"

AC_SUBST([AM_CPPFLAGS])

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
AC_MSG_RESULT([
    $PACKAGE $VERSION

    prefix:         ${prefix}
    sysconfdir:     ${sysconfdir}
    libdir:         ${libdir}
    includedir:     ${includedir}

    compiler++:      ${CXX}
    cppflags:        ${CPPFLAGS}
    am_cppflags:     ${AM_CPPFLAGS}
    cxxflags:        ${CXXFLAGS}
    am_cxxflags:     ${AM_CXXFLAGS}
    ldflags:         ${LDFLAGS}
    am_ldflags:      ${AM_LDFLAGS}
    libs:            ${LIBS}
])
