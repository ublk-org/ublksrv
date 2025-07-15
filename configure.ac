# ublksrv
# Copyright (C) Ming Lei
# SPDX-License-Identifier: MIT or GPL-2.0-only

AC_INIT([ublksrv],
		m4_esyscmd(utils/genver.sh | tr -d '\n'),
		[https://github.com/ming1/ubdsrv],,
		[https://github.com/ming1/ubdsrv])

AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],[],
         [m4_define([AC_USE_SYSTEM_EXTENSIONS],[])])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AM_SILENT_RULES([yes])

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

AX_PTHREAD

dnl Check for C++.
AC_PROG_CXX

AS_CASE([$CXX],
  [*clang++*], [ENABLE_CORO_FLAG=""],
  [*g++*], [ENABLE_CORO_FLAG="-fcoroutines"],
  [ENABLE_CORO_FLAG=""]
)

CXXFLAGS="$CXXFLAGS $ENABLE_CORO_FLAG"


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

AC_ARG_ENABLE(
  debug,
  AS_HELP_STRING([--enable-debug],[Build a debug version of ublk(default disabled)]),
  [
    if test "x$enableval" = "xyes"; then
      AC_DEFINE(DEBUG, 1, [Define to 1 if you want to build debug version])
    fi
  ]
)

dnl Check for liburing (required).
PKG_CHECK_MODULES([LIBURING], [liburing >= 2.2])

dnl Check if io_uring_prep_sendmsg_zc which isn't supported on 2.2 yet
AC_MSG_CHECKING([for io_uring_prep_sendmsg_zc])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
  #include <liburing.h>
]], [[
	 int i = IORING_CQE_F_NOTIF;
]])],
[AC_MSG_RESULT([yes])
 AM_CONDITIONAL([HAVE_LIBURING_SEND_ZC], true)
 AC_DEFINE([HAVE_LIBURING_SEND_ZC], [1], [Define to 1 if liburing supports send zc])],
[AC_MSG_RESULT([no])
 AM_CONDITIONAL([HAVE_LIBURING_SEND_ZC], false)])

dnl Check for libnfs api v2
AC_ARG_WITH([libnfs],
	[AS_HELP_STRING([--without-libnfs],
		[do not use libnfs])],
	[],
	[with_libnfs=check]
)
if test "x$with_libnfs" != "xno"; then
    	AC_MSG_CHECKING([for libnfs api v2])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stddef.h>
#include <nfsc/libnfs.h>
	]], [[
#ifndef LIBNFS_API_V2
		does not compile
#endif
		nfs_mt_service_thread_start(NULL);
	]])],
	[AC_MSG_RESULT([yes])
	 AM_CONDITIONAL([HAVE_LIBNFS], true)
	 AC_DEFINE([HAVE_LIBNFS], [1], [Define to 1 if libnfs api v2 is available])],
	[AC_MSG_RESULT([no])
	 AM_CONDITIONAL([HAVE_LIBNFS], false)])
else
	 AM_CONDITIONAL([HAVE_LIBNFS], false)
fi
AM_CONDITIONAL([LIBNFS], [test "x$HAVE_LIBNFS" = "x1"])

dnl Check for libiscsi
AC_ARG_WITH([libiscsi],
	[AS_HELP_STRING([--without-libiscsi],
		[do not use libiscsi])],
	[],
	[with_libiscsi=check]
)
if test "x$with_libiscsi" != "xno"; then
    	AC_MSG_CHECKING([for libiscsi])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <iscsi/iscsi.h>
	]], [[
		int i = LIBISCSI_IMMEDIATE_SOCKET_WRITE;
	]])],
	[AC_MSG_RESULT([yes])
	 AM_CONDITIONAL([HAVE_LIBISCSI], true)
	 AC_DEFINE([HAVE_LIBISCSI], [1], [Define to 1 if libiscsi is available])],
	[AC_MSG_RESULT([no])
	 AM_CONDITIONAL([HAVE_LIBISCSI], false)])
else
	 AM_CONDITIONAL([HAVE_LIBISCSI], false)
fi
AM_CONDITIONAL([LIBISCSI], [test "x$HAVE_LIBISCSI" = "x1"])

#gnutls is only for nbd target, borrowed from nbd-client project
AC_ARG_WITH([gnutls],
	[AS_HELP_STRING([--without-gnutls],
		[do not use gnutls])],
	[],
	[with_gnutls=check]
)
if test "x$with_gnutls" != "xno"; then
	PKG_CHECK_MODULES(GnuTLS, [gnutls >= 2.12.0],
		[HAVE_GNUTLS=1
		AC_DEFINE(HAVE_GNUTLS, 1, [Define to 1 if you have a GnuTLS version of 2.12 or above])],
		[if test "x$with_gnutls" = "xyes"; then
			AC_MSG_ERROR([--with-gnutls given but cannot find gnutls])
		else
			HAVE_GNUTLS=0
			AC_DEFINE(HAVE_GNUTLS, 0)
		fi]
	)
else
	HAVE_GNUTLS=0
	AC_DEFINE(HAVE_GNUTLS, 0)
fi
AM_CONDITIONAL([GNUTLS], [test "x$HAVE_GNUTLS" = "x1"])

AC_ARG_ENABLE(
  sdp,
  AS_HELP_STRING([--enable-sdp],[Build a version of nbd-server with support for the Socket Direct Protocol (SDP). Requires you to build and install a kernel with the InfiniBand patches (default disabled)]),
  [
    if test "x$enableval" = "xyes"; then
      AC_DEFINE(WITH_SDP, 1, [Define to 1 if you have and want support for the Socket Direct Protocol])
    fi
  ]
)

AC_ARG_ENABLE(
  lfs,
  AS_HELP_STRING([--disable-lfs],[Disable Large File Support (default on)]),
  [
    if test "x$enableval" = "xyes" ; then
      NBD_LFS=1
    else
      NBD_LFS=0
    fi
  ],
  [NBD_LFS=1]
)
AC_MSG_CHECKING([whether Large File Support should be enabled])
if test $NBD_LFS -eq 1; then
  AC_DEFINE(NBD_LFS,1, [Define to 1 if Large File Support should be enabled])
  AC_MSG_RESULT([yes])
else
  AC_DEFINE(NBD_LFS,0)
  AC_MSG_RESULT([no])
fi

ublk_control=/dev/ublk-control
AC_ARG_WITH(
  [ublk_control],
  [AS_HELP_STRING([--with-ublk_control], [Set the ublk control device. Defaults to /dev/ublk-control.])],
  [ublk_control="$withval"]
  [],
)
AC_DEFINE_UNQUOTED([UBLK_CONTROL], ["${ublk_control}"], [ublk control device.])

ublkc_prefix=/dev
AC_ARG_WITH(
  [ublkc_prefix],
  [AS_HELP_STRING([--with-ublkc_prefix], [Set the directory prefix for ublkc devices. Defaults to /dev.])],
  [ublkc_prefix="$withval"]
  [],
)
AC_DEFINE_UNQUOTED([UBLKC_PREFIX], ["${ublkc_prefix}"], [prefix for ublkc devices.])

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN"; then
   AC_MSG_WARN([Doxygen not found - continue without Doxygen support])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])

dnl Produce output files.
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 include/Makefile
                 lib/Makefile
                 tests/Makefile
                 ublksrv.pc])

AC_OUTPUT
