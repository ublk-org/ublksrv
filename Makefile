CC = gcc
CFLAGS = -g -D_GNU_SOURCE -MMD
LIBS = -lrt -lpthread

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

TOP_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

UBDSRV_OBJS = ubdsrv_cmd.o ubdsrv.o ubdsrv_uring.o utils.o ubdsrv_tgt.o tgt_null.o tgt_loop.o
UBDSRV_PROGS = ubd

R = 10

all:$(UBDSRV_PROGS)

-include $(UBDSRV_OBJS:%.o=%.d)

$(UBDSRV_PROGS): $(UBDSRV_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(UBDSRV_OBJS) $(LIBS)

.PHONY: clean test loop_test null_test
clean:
	rm -f  $(UBDSRV_PROGS) $(UBDSRV_OBJS)
	rm -f *~ *.d
	make -s -C ${TOP_DIR}tests clean

test: $(UBDSRV_PROGS)
	make -s -C ${TOP_DIR}tests run T=${T} R=${R}

test_all: $(UBDSRV_PROGS)
	make -s -C ${TOP_DIR}tests run_test_all R=${R}
