CC = g++
CFLAGS = -g -O2 -D_GNU_SOURCE -MMD -fcoroutines -std=c++20 -I /root/git/liburing/src/include/
LIBS = -lrt -lpthread -L/root/git/liburing/src -luring

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

TOP_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

UBDSRV_OBJS = ubdsrv_cmd.o ubdsrv.o utils.o ubdsrv_tgt.o tgt_null.o tgt_loop.o
UBDSRV_PROGS = ubd

R = 10

all:$(UBDSRV_PROGS)

-include $(UBDSRV_OBJS:%.o=%.d)

$(UBDSRV_PROGS): $(UBDSRV_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(UBDSRV_OBJS) $(LIBS)

.PHONY: clean test test_all cscope
clean:
	rm -f  $(UBDSRV_PROGS) $(UBDSRV_OBJS)
	rm -f *~ *.d
	make -s -C ${TOP_DIR}tests clean
	rm -f cscope.*

test: $(UBDSRV_PROGS)
	make -s -C ${TOP_DIR}tests run T=${T} R=${R}

test_all: $(UBDSRV_PROGS)
	make -s -C ${TOP_DIR}tests run_test_all R=${R}

cscope:
	find . -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" > cscope.files
	cscope -q -b -f cscope.out
