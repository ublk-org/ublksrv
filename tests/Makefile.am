# SPDX-License-Identifier: MIT or GPL-2.0-only

# XXX Fix to use autotools TESTS = ...

.PHONY: run clean

run:
	$(srcdir)/run_test.sh ${T} ${R} ${D}

CLEANFILES = *~ */*~

# Keep in sync with the test files tracked in git; 'make
# maintainer-check-extra-dist' at the top level flags anything missing.
EXTRA_DIST = \
	common/fio_common \
	common/loop_common \
	common/nbd_common \
	debug/test_dev \
	debug/ublk_docker \
	generic/001 \
	generic/002 \
	generic/003 \
	generic/004 \
	generic/005 \
	generic/006 \
	generic/007 \
	generic/008 \
	loop/001 \
	loop/002 \
	loop/003 \
	loop/004 \
	loop/005 \
	loop/006 \
	loop/007 \
	loop/008 \
	loop/009 \
	loop/010 \
	loop/012 \
	loop/013 \
	nbd/001 \
	nbd/002 \
	nbd/003 \
	nbd/021 \
	nbd/022 \
	nbd/023 \
	nbd/024 \
	nbd/041 \
	nbd/042 \
	nbd/043 \
	nbd/044 \
	nbd/045 \
	nbd/046 \
	null/001 \
	null/002 \
	null/004 \
	null/005 \
	null/006 \
	null/007 \
	null/012 \
	run_test.sh
