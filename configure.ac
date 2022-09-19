# ublksrv
# Copyright (C) Ming Lei
# SPDX-License-Identifier: MIT or GPL-2.0-only

AC_INIT([ublksrv],[1.0])

AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],[],
         [m4_define([AC_USE_SYSTEM_EXTENSIONS],[])])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

dnl NB: Do not [quote] this parameter.
AM_INIT_AUTOMAKE(foreign)
LT_INIT

AC_CANONICAL_HOST

AC_PROG_SED

dnl Check for basic C environment.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_CPP

AC_C_PROTOTYPES
test "x$U" != "x" && AC_MSG_ERROR([Compiler not ANSI compliant])

AM_PROG_CC_C_O

m4_ifdef([AX_PTHREAD],,
 [m4_fatal([The m4 macro AX_PTHREAD has not been defined. Please install the autoconf-archive package.])])
AX_PTHREAD

dnl Check for C++.
AC_PROG_CXX

dnl --enable-gcc-warnings to turn on GCC warnings (for developers).
AC_ARG_ENABLE([gcc-warnings],
    [AS_HELP_STRING([--enable-gcc-warnings],
                    [turn on lots of GCC warnings (for developers)])],
     [case $enableval in
      yes|no) ;;
      *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
      esac
      gcc_warnings=$enableval],
      [gcc_warnings=no]
)
if test "x$gcc_warnings" = "xyes"; then
    # Enable normal GCC warnings and a few more:
    #  - Warn about variable length arrays on stack.
    #  - Warn about large stack frames (since we may be used from threads).
    WARNINGS_CFLAGS="-Wall -Werror"
    AC_C_COMPILE_FLAGS([WARNINGS_CFLAGS],
                       [-Wvla -Wframe-larger-than=5000 -Wstack-usage=10000],
                       [$CFLAGS -Werror])
    AC_SUBST([WARNINGS_CFLAGS])
fi

dnl Check for liburing (required).
PKG_CHECK_MODULES([LIBURING], [liburing >= 2.2])

dnl Produce output files.
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 lib/Makefile
                 tests/Makefile
                 ublksrv.pc])

#
# Check if g++ supports -fcoroutines -std=c++20
#
AC_LANG_PUSH([C++])
CXXFLAGS_save=$CXXFLAGS
CXXFLAGS="$CXXFLAGS -fcoroutines -std=c++20"
T001_PROGRAM="
#include <coroutine>
int main(void) {
	return 0;
}
"
AC_MSG_CHECKING([whether $CXX supports -fcoroutines -std=c++20])
AC_COMPILE_IFELSE(
	[AC_LANG_SOURCE([$T001_PROGRAM])],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_FAILURE([no])]
)

CXXFLAGS=$CXXFLAGS_save
AC_LANG_POP([C++])

#
# Only support kernel 5.19 and beyond
#
linux_kernel_ver=$(uname -r)
AX_COMPARE_VERSION($linux_kernel_ver, [ge], [5.19],
    [AC_MSG_NOTICE([checking for kernel version >= 5.19.X. Found... $linux_kernel_ver])],
    [AC_MSG_ERROR([Expected Kernel Version >= 5.19.X. Found... $linux_kernel_ver]),[1]])


AC_OUTPUT
