AC_DEFUN([AC_CHECK_DAQ],
[
    PKG_CHECK_MODULES([LIBDAQ], [libdaq],
        [HAVE_DAQ="yes"],
        [HAVE_DAQ="no"])
])
