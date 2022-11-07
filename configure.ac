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
AM_INIT_AUTOMAKE([foreign subdir-objects])
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
    #
    # TODO: Address 'sign-compare' errors and remove -Wno-sign-compare
    # TODO: Address 'parentheses' errors and remove -Wno-parentheses
    WARNINGS_CFLAGS="-Wall -Werror -Wuninitialized -Wmaybe-uninitialized -Wno-sign-compare -Wno-parentheses"
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

AC_OUTPUT
