CC = g++
CFLAGS = -g -O2 -D_GNU_SOURCE -MMD -fcoroutines -std=c++20 -I /root/git/liburing/src/include/
LIBS = -lrt -lpthread -L/root/git/liburing/src -luring

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

TOP_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

UBLKSRV_OBJS = ublksrv_cmd.o ublksrv.o utils.o ublksrv_tgt.o tgt_null.o tgt_loop.o
UBLKSRV_PROGS = ublk

R = 10

all:$(UBLKSRV_PROGS)

-include $(UBLKSRV_OBJS:%.o=%.d)

$(UBLKSRV_PROGS): $(UBLKSRV_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(UBLKSRV_OBJS) $(LIBS)

.PHONY: clean test test_all cscope
clean:
	rm -f  $(UBLKSRV_PROGS) $(UBLKSRV_OBJS)
	rm -f *~ *.d
	make -s -C ${TOP_DIR}tests clean
	rm -f cscope.*

test: $(UBLKSRV_PROGS)
	make -s -C ${TOP_DIR}tests run T=${T} R=${R}

test_all: $(UBLKSRV_PROGS)
	make -s -C ${TOP_DIR}tests run_test_all R=${R}

cscope:
	find . -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" > cscope.files
	cscope -q -b -f cscope.out
