DEFAULT: libradauth.so radauth_test radauth_test_threaded

CC = gcc

ifdef DEBUG
DFLAGS = -DDEBUG -g
else
DFLAGS =
endif

ifndef NO_LOCALLIB
LOCAL_LIB_FLAGS = -Wl,-rpath="$(shell pwd)" -L.
endif

CFLAGS = -Wall -Werror -fstack-protector-all -D_FORTIFY_SOURCE=2

SONAME = libradauth.so.0
FREERADIUS_CPPFLAGS = -I/usr/include/freeradius
FREERADIUS_LDFLAGS = -L/usr/lib/freeradius -rpath /usr/lib/freeradius -soname=$(SONAME)
FREERADIUS_LIBS = -lfreeradius-radius -lpthread -lc

radauth_test: radauth_test.c Makefile libradauth.so
	$(CC) $(CFLAGS) $(DFLAGS) $(LOCAL_LIB_FLAGS) -lradauth -o radauth_test radauth_test.c
radauth_test_threaded: radauth_test_threaded.c Makefile libradauth.so
	$(CC) $(CFLAGS) $(DFLAGS) $(LOCAL_LIB_FLAGS) -lradauth -pthread -o radauth_test_threaded radauth_test_threaded.c
libradauth.o: libradauth.c libradauth.h Makefile
	$(CC) $(CFLAGS) $(DFLAGS) $(FREERADIUS_CPPFLAGS) -fPIC -c libradauth.c
libradauth.so: libradauth.o
	ld $(FREERADIUS_LDFLAGS) -shared -o $(SONAME) libradauth.o \
	    $(FREERADIUS_LIBS)
	ln -sf $(SONAME) libradauth.so

clean:
	rm -f libradauth.o libradauth.so radauth_test radauth_test_threaded $(SONAME)
