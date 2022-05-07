CC = gcc
CFLAGS = -g -D_GNU_SOURCE -MMD
LIBS = -lrt -lpthread

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

UBDSRV_OBJS = ubdsrv_cmd.o ubdsrv.o ubdsrv_uring.o utils.o ubdsrv_tgt.o tgt_null.o tgt_loop.o
UBDSRV_PROGS = ubd

all:$(UBDSRV_PROGS)

-include $(UBDSRV_OBJS:%.o=%.d)

$(UBDSRV_PROGS): $(UBDSRV_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(UBDSRV_OBJS) $(LIBS)

.PHONY: clean
clean:
	rm -f  $(UBDSRV_PROGS) $(UBDSRV_OBJS)
	rm -f *~ *.d
