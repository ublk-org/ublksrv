# SPDX-License-Identifier: MIT or GPL-2.0-only

include Makefile.common

TOP_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
override CFLAGS += -I include

UBLKSRV_OBJS = ublksrv_tgt.o tgt_null.o tgt_loop.o
UBLKSRV_PROG = ublk
PROG_DEMO = demo_null
PROG_DEMO2 = demo_event
UBLKSRV_PROGS = $(UBLKSRV_PROG) $(PROG_DEMO) $(PROG_DEMO2)
LIBUBLKSRV = lib/libublksrv.a

all: $(LIBUBLKSRV) $(UBLKSRV_PROGS)

-include $(UBLKSRV_OBJS:%.o=%.d)

%.o : %.c Makefile
	$(CPP) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(LIBUBLKSRV):
	make -C ${TOP_DIR}lib

$(UBLKSRV_PROG): $(LIBUBLKSRV) $(UBLKSRV_OBJS)
	$(CPP) -o $@ $(UBLKSRV_OBJS) $(LIBUBLKSRV) $(LDFLAGS)

$(PROG_DEMO): $(LIBUBLKSRV) demo_null.o
	$(CPP) -o $@ demo_null.o $(LDFLAGS) -L./lib -lublksrv -Wl,-rpath,$(TOP_DIR)lib
$(PROG_DEMO2): $(LIBUBLKSRV) demo_event.o
	$(CPP) -o $@ demo_event.o $(LDFLAGS) -L./lib -lublksrv -Wl,-rpath,$(TOP_DIR)lib

.PHONY: clean test cscope
clean:
	rm -f $(UBLKSRV_PROGS) $(UBLKSRV_OBJS) $(UBLKSRV_LIB_OBJS) $(UBLKSRV_LIB)
	rm -f $(PROG_DEMO) $(PROG_DEMO).o
	rm -f $(PROG_DEMO2) $(PROG_DEMO2).o
	rm -f *~ *.d include/*~
	make -s -C ${TOP_DIR}tests clean
	make -s -C ${TOP_DIR}lib clean
	rm -f cscope.*

R = 10
test: $(UBLKSRV_PROGS)
	make -s -C ${TOP_DIR}tests run T=${T} R=${R}

cscope:
	@cscope -b -R
