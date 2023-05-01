# SPDX-License-Identifier: MIT or GPL-2.0-only

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	COPYING.LGPL \
	.gitignore \
	LICENSE

SUBDIRS = include lib tests

AM_CXXFLAGS = -fcoroutines -std=c++20

sbin_PROGRAMS = ublk ublk_user_id
noinst_PROGRAMS = demo_null demo_event
dist_sbin_SCRIPTS = utils/ublk_chown.sh utils/ublk_chown_docker.sh

ublk_SOURCES = ublksrv_tgt.cpp tgt_null.cpp tgt_loop.cpp qcow2/tgt_qcow2.cpp \
			   qcow2/qcow2.cpp qcow2/qcow2_meta.cpp qcow2/utils.cpp \
			   qcow2/qcow2_flush_meta.cpp \
			   nbd/tgt_nbd.cpp nbd/cliserv.c nbd/nbd-client.c
ublk_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_CPPFLAGS = $(ublk_CFLAGS) -I$(top_srcdir)/include
ublk_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

demo_null_SOURCES = demo_null.c
demo_null_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
demo_null_CPPFLAGS = $(demo_null_CFLAGS) -I$(top_srcdir)/include
demo_null_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

demo_event_SOURCES = demo_event.c
demo_event_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
demo_event_CPPFLAGS = $(demo_event_CFLAGS) -I$(top_srcdir)/include
demo_event_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

ublk_user_id_SOURCES = utils/ublk_user_id.c
ublk_user_id_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_user_id_CPPFLAGS = $(ublk_user_id_CFLAGS) -I$(top_srcdir)/include
ublk_user_id_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ublksrv.pc

CLEANFILES = *~ test cscope.* include/*~ *.d qcow2/*~ nbd/*~ utils/*~ doc/html/*

R = 10
D = tests/tmp/
test: $(sbin_PROGRAMS) $(noinst_PROGRAMS)
	make -C tests run T=${T} R=${R} D=${D}

cscope:
	@cscope -b -R

if HAVE_DOXYGEN
doxygen_doc:
	doxygen doc/Doxyfile
endif

# Check no files are missing from EXTRA_DIST rules, and that all
# generated files have been included in the tarball.  (Note you must
# have done 'make dist')
maintainer-check-extra-dist:
	@zcat $(PACKAGE_NAME)-$(VERSION).tar.gz | tar tf - | sort | \
	    sed 's,^$(PACKAGE_NAME)-$(VERSION)/,,' > tarfiles
	@git ls-files | \
	    sort > gitfiles
	@comm -13 tarfiles gitfiles > comm-out
	@echo Checking for differences between EXTRA_DIST and git ...
	@cat comm-out
	@[ ! -s comm-out ]
	@rm tarfiles gitfiles comm-out
	@echo PASS: EXTRA_DIST tests
