AC_DEFUN([AC_CHECK_DAQ_HEADERS],
[
    AC_ARG_WITH(libdaq_includes,
                AS_HELP_STRING([--with-libdaq-includes=DIR],[libdaq include directory]),
                [], [with_libdaq_includes="no"])

    if test "x$with_libdaq_includes" != "xno"; then
        LIBDAQ_CPPFLAGS="-I${with_libdaq_includes}"
    fi

    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $LIBDAQ_CPPFLAGS"
    AC_CHECK_HEADER([daq_api.h], [HAVE_DAQ_HEADERS="yes"], [HAVE_DAQ_HEADERS="no"])
    CPPFLAGS="$save_CPPFLAGS"
])

AC_DEFUN([AC_CHECK_DAQ_LIBS],
[
    AC_ARG_WITH(libdaq_libraries,
                AS_HELP_STRING([--with-libdaq-libraries=DIR],[libdaq library directory]),
                [], [with_libdaq_libraries="no"])

    if test "x$with_libdaq_libraries" != "xno"; then
        LIBDAQ_LDFLAGS="-L${with_libdaq_libraries}"
    fi

    save_LDFLAGS="$LDFLAGS"
    save_LIBS="$LIBS"
    LDFLAGS="$LDFLAGS $LIBDAQ_LDFLAGS"
    AC_CHECK_LIB([daq], [daq_load_modules], [HAVE_DAQ_LIBRARIES="yes"], [HAVE_DAQ_LIBRARIES="no"])
    LIBS="$save_LIBS"
    LDFLAGS="$save_LDFLAGS"
])

AC_DEFUN([AC_CHECK_SFBPF_HEADERS],
[
    AC_ARG_WITH(libsfbpf_includes,
                AS_HELP_STRING([--with-libsfbpf-includes=DIR],[libsfbpf include directory]),
                [], [with_libsfbpf_includes="no"])

    if test "x$with_libsfbpf_includes" != "xno"; then
        LIBSFBPF_CPPFLAGS="-I${with_libsfbpf_includes}"
    fi

    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $LIBSFBPF_CPPFLAGS"
    AC_CHECK_HEADER([sfbpf.h], [HAVE_SFBPF_HEADERS="yes"], [HAVE_SFBPF_HEADERS="no"])
    CPPFLAGS="$save_CPPFLAGS"
])

AC_DEFUN([AC_CHECK_SFBPF_LIBS],
[
    AC_ARG_WITH(libsfbpf_libraries,
                AS_HELP_STRING([--with-libsfbpf-libraries=DIR],[libsfbpf library directory]),
                [], [with_libsfbpf_libraries="no"])

    if test "x$with_libsfbpf_libraries" != "xno"; then
        LIBSFBPF_LDFLAGS="-L${with_libsfbpf_libraries}"
    fi

    save_LDFLAGS="$LDFLAGS"
    save_LIBS="$LIBS"
    LDFLAGS="$LDFLAGS $LIBSFBPF_LDFLAGS"
    AC_CHECK_LIB([sfbpf], [sfbpf_compile], [HAVE_SFBPF_LIBRARIES="yes"], [HAVE_SFBPF_LIBRARIES="no"])
    LIBS="$save_LIBS"
    LDFLAGS="$save_LDFLAGS"
])

