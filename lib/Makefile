
include ../Makefile.common

override CFLAGS += -fPIC -I ../include

UBLKSRV_LIB = libublksrv.so
UBLKSRV_LIB_STATIC = libublksrv.a
UBLKSRV_LIB_OBJS = ublksrv_cmd.o ublksrv.o

all: $(UBLKSRV_LIB) $(UBLKSRV_LIB_STATIC)

-include $(UBLKSRV_LIB_OBJS:%.o=%.d)

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(UBLKSRV_LIB): $(UBLKSRV_LIB_OBJS)
	$(CC) -shared -o $@  $(UBLKSRV_LIB_OBJS) $(LDFLAGS)

$(UBLKSRV_LIB_STATIC): $(UBLKSRV_LIB_OBJS)
	$(AR) rcs $@ $^

.PHONY: clean
clean:
	rm -f  $(UBLKSRV_LIB_OBJS) $(UBLKSRV_LIB) $(UBLKSRV_LIB_STATIC)
	rm -f *~ *.d
