# SPDX-License-Identifier: MIT or GPL-2.0-only

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	COPYING.LGPL \
	.gitignore \
	LICENSE

SUBDIRS = doc include lib tests

AM_CXXFLAGS = -std=c++20 -Wunused

TGT_DIR = targets
TGT_INC = $(top_srcdir)/$(TGT_DIR)/include

sbin_PROGRAMS = ublk ublk.null ublk.loop ublk.nbd ublk.nvme_vfio ublk.sheepdog ublk_user_id
noinst_PROGRAMS = demo_null demo_event
dist_sbin_SCRIPTS = utils/ublk_chown.sh utils/ublk_chown_docker.sh

if HAVE_LIBNFS
sbin_PROGRAMS += ublk.nfs
endif

if HAVE_LIBISCSI
sbin_PROGRAMS += ublk.iscsi
endif

ublk_SOURCES = $(TGT_DIR)/ublk.cpp $(TGT_DIR)/ublksrv_tgt.cpp

ublk_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_CPPFLAGS = $(ublk_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

ublk_null_SOURCES = $(TGT_DIR)/ublk.null.cpp $(TGT_DIR)/ublksrv_tgt.cpp
ublk_null_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_null_CPPFLAGS = $(ublk_null_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_null_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

ublk_iscsi_SOURCES = $(TGT_DIR)/ublk.iscsi.cpp $(TGT_DIR)/ublksrv_tgt.cpp
ublk_iscsi_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_iscsi_CPPFLAGS = $(ublk_iscsi_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_iscsi_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS) -liscsi

ublk_loop_SOURCES = $(TGT_DIR)/ublk.loop.cpp $(TGT_DIR)/ublksrv_tgt.cpp
ublk_loop_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_loop_CPPFLAGS = $(ublk_loop_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_loop_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

ublk_nbd_SOURCES = $(TGT_DIR)/nbd/ublk.nbd.cpp $(TGT_DIR)/nbd/cliserv.c $(TGT_DIR)/nbd/nbd-client.c $(TGT_DIR)/ublksrv_tgt.cpp
ublk_nbd_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_nbd_CPPFLAGS = $(ublk_nbd_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_nbd_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

ublk_nvme_vfio_SOURCES = $(TGT_DIR)/nvme/ublk.nvme_vfio.cpp $(TGT_DIR)/ublksrv_tgt.cpp
ublk_nvme_vfio_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_nvme_vfio_CPPFLAGS = $(ublk_nvme_vfio_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_nvme_vfio_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

ublk_sheepdog_SOURCES = $(TGT_DIR)/sheepdog/ublk.sheepdog.cpp $(TGT_DIR)/sheepdog/sheep.c $(TGT_DIR)/ublksrv_tgt.cpp
ublk_sheepdog_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_sheepdog_CPPFLAGS = $(ublk_sheepdog_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_sheepdog_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS)

ublk_nfs_SOURCES = $(TGT_DIR)/ublk.nfs.cpp $(TGT_DIR)/ublksrv_tgt.cpp
ublk_nfs_CFLAGS = $(WARNINGS_CFLAGS) $(LIBURING_CFLAGS) $(PTHREAD_CFLAGS)
ublk_nfs_CPPFLAGS = $(ublk_nfs_CFLAGS) -I$(top_srcdir)/include -I$(TGT_INC)
ublk_nfs_LDADD = lib/libublksrv.la $(LIBURING_LIBS) $(PTHREAD_LIBS) -lnfs

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

CLEANFILES = *~ test cscope.* include/*~ *.d nbd/*~ utils/*~ doc/html/*

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
