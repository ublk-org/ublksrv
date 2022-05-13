CC = gcc
CFLAGS = -g -D_GNU_SOURCE -MMD
LIBS = -lrt -lpthread

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

TOP_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

UBDSRV_OBJS = ubdsrv_cmd.o ubdsrv.o ubdsrv_uring.o utils.o ubdsrv_tgt.o tgt_null.o tgt_loop.o
UBDSRV_PROGS = ubd

all:$(UBDSRV_PROGS)

-include $(UBDSRV_OBJS:%.o=%.d)

$(UBDSRV_PROGS): $(UBDSRV_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(UBDSRV_OBJS) $(LIBS)

.PHONY: clean test loop_test null_test
clean:
	rm -f  $(UBDSRV_PROGS) $(UBDSRV_OBJS)
	rm -f *~ *.d
	rm -f ./test/*~

test:
	make -C ${TOP_DIR}tests test

loop_test:
	make -C ${TOP_DIR}tests loop

null_test:
	make -C ${TOP_DIR}tests null
