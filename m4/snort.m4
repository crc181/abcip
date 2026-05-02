AC_DEFUN([AC_CHECK_SNORT],
[
    PKG_CHECK_MODULES([LIBSNORT], [snort],
        [HAVE_SNORT="yes"],
        [HAVE_SNORT="no"])

    if test "x$HAVE_SNORT" = "xyes"; then
        # snort.pc exposes DAQ_CPPFLAGS as a variable; extract it so the
        # logger can include <daq_common.h> which packet.h requires.
        DAQ_CPPFLAGS=$(pkg-config --variable=DAQ_CPPFLAGS snort 2>/dev/null || true)
        if test -n "$DAQ_CPPFLAGS"; then
            LIBSNORT_CFLAGS="$LIBSNORT_CFLAGS $DAQ_CPPFLAGS"
        fi
        AC_SUBST([LIBSNORT_CFLAGS])
    fi
])
