CC = g++
LIBCFLAGS = -g -O2 -D_GNU_SOURCE -MMD -fPIC -I /root/git/liburing/src/include/
CFLAGS = -fcoroutines -std=c++20 $(LIBCFLAGS)
LIBS = -lrt -lpthread -L/root/git/liburing/src -luring

TOP_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

UBLKSRV_LIB = libublksrv.so
#UBLKSRV_LIB_STATIC = libublksrv.a
UBLKSRV_LIB_OBJS = ublksrv_cmd.o ublksrv.o
UBLKSRV_OBJS = utils.o ublksrv_tgt.o tgt_null.o tgt_loop.o
UBLKSRV_PROGS = ublk
R = 10

all: $(UBLKSRV_PROGS) $(UBLKSRV_LIB)

-include $(UBLKSRV_OBJS:%.o=%.d)
-include $(UBLKSRV_LIB_OBJS:%.o=%.d)

ublksrv_cmd.o: ublksrv_cmd.c Makefile
	$(CC) -c $(LIBCFLAGS) $(CPPFLAGS) $< -o $@
ublksrv.o: ublksrv.c Makefile
	$(CC) -c $(LIBCFLAGS) $(CPPFLAGS) $< -o $@

utils.o: utils.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
ublksrv_tgt.o: ublksrv_tgt.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
tgt_null.o: tgt_null.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
tgt_loop.o: tgt_loop.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(UBLKSRV_PROGS): $(UBLKSRV_OBJS) $(UBLKSRV_LIB)
	$(CC) $(LDFLAGS) -o $@ $(UBLKSRV_OBJS) $(LIBS) -L. -lublksrv -Wl,-rpath,$(TOP_DIR)

$(UBLKSRV_LIB): $(UBLKSRV_LIB_OBJS)
	$(CC) -shared ${LDFLAGS} -o $@  $(UBLKSRV_LIB_OBJS) $(LIBS)

.PHONY: clean test test_all cscope
clean:
	rm -f  $(UBLKSRV_PROGS) $(UBLKSRV_OBJS) $(UBLKSRV_LIB_OBJS) $(UBLKSRV_LIB)
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
