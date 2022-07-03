CC = g++
CFLAGS = -g -O2 -D_GNU_SOURCE -MMD -fPIC -I ../include  -I /root/git/liburing/src/include/
LIBS = -lrt -lpthread -L/root/git/liburing/src -luring
AR = ar

UBLKSRV_LIB = libublksrv.so
UBLKSRV_LIB_STATIC = libublksrv.a
UBLKSRV_LIB_OBJS = ublksrv_cmd.o ublksrv.o

all: $(UBLKSRV_LIB) $(UBLKSRV_LIB_STATIC)

-include $(UBLKSRV_LIB_OBJS:%.o=%.d)

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

$(UBLKSRV_LIB): $(UBLKSRV_LIB_OBJS)
	$(CC) -shared ${LDFLAGS} -o $@  $(UBLKSRV_LIB_OBJS) $(LIBS)

$(UBLKSRV_LIB_STATIC): $(UBLKSRV_LIB_OBJS)
	$(AR) rcs $@ $^

.PHONY: clean
clean:
	rm -f  $(UBLKSRV_LIB_OBJS) $(UBLKSRV_LIB) $(UBLKSRV_LIB_STATIC)
	rm -f *~ *.d
