# SPDX-License-Identifier: MIT or GPL-2.0-only

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	COPYING.LGPL \
	.gitignore \
	LICENSE

SUBDIRS = include lib tests

AM_CXXFLAGS = -fcoroutines -std=c++20

sbin_PROGRAMS = ublk
noinst_PROGRAMS = demo_null demo_event

ublk_SOURCES = ublksrv_tgt.cpp tgt_null.cpp tgt_loop.cpp
ublk_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_CPPFLAGS = -I$(top_srcdir)/include
ublk_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

demo_null_SOURCES = demo_null.c
demo_null_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
demo_null_CPPFLAGS = -I$(top_srcdir)/include
demo_null_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

demo_event_SOURCES = demo_event.c
demo_event_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
demo_event_CPPFLAGS = -I$(top_srcdir)/include
demo_event_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

CLEANFILES = *~ test cscope.* include/*~ *.d

R = 10
test: $(sbin_PROGRAMS) $(noinst_PROGRAMS)
	make -C tests run T=${T} R=${R}

cscope:
	@cscope -b -R
