# SPDX-License-Identifier: MIT or GPL-2.0-only

# XXX Fix to use autotools TESTS = ...

.PHONY: run clean

run:
	$(srcdir)/run_test.sh ${T} ${R} ${D}

CLEANFILES = *~ */*~

EXTRA_DIST = \
	common/fio_common \
	common/loop_common \
	generic/001 \
	generic/002 \
	generic/003 \
	loop/001 \
	loop/002 \
	loop/003 \
	loop/004 \
	loop/005 \
	loop/006 \
	loop/007 \
	null/001 \
	null/002 \
	null/004 \
	null/005 \
	null/006 \
	run_test.sh
