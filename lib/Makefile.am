# SPDX-License-Identifier: MIT or LGPL-2.1-only

lib_LTLIBRARIES = libublksrv.la

libublksrv_la_SOURCES = \
	ublksrv_cmd.c \
	ublksrv_json.cpp \
	ublksrv.c \
	utils.c \
	ublksrv_aio.c
libublksrv_la_CFLAGS = \
	$(WARNING_CFLAGS) \
	$(LIBURING_CFLAGS) \
	$(PTHREAD_CFLAGS) -DUBLKSRV_INTERNAL_H_
libublksrv_la_CPPFLAGS = \
	-I$(top_srcdir)/include -DUBLKSRV_INTERNAL_H_
libublksrv_la_LIBADD = \
	$(LIBURING_LIBS) \
	$(PTHREAD_LIBS)
libublksrv_la_LDFLAGS = \
	-version-info 0:0:0

CLEANFILES = *~ *.d
