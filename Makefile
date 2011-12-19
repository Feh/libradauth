DEFAULT: libradauth.so radauth_test

ifdef DEBUG
DFLAGS = -DDEBUG -g
else
DGLAGS =
endif

FREERADIUS_CPPFLAGS = -I/usr/include/freeradius
FREERADIUS_LDFLAGS = -L/usr/lib/freeradius -rpath /usr/lib/freeradius
FREERADIUS_LIBS = -lfreeradius-radius -lpthread

radauth_test: radauth_test.c Makefile
	gcc $(DFLAGS) -Wl,-rpath,./ -L. -lradauth -o radauth_test radauth_test.c
libradauth.o: libradauth.c libradauth.h Makefile
	gcc $(DFLAGS) $(FREERADIUS_CPPFLAGS) -fPIC -c libradauth.c
libradauth.so: libradauth.o
	ld $(FREERADIUS_LDFLAGS) -shared -o libradauth.so libradauth.o \
	    $(FREERADIUS_LIBS)

clean:
	rm -f libradauth.o libradauth.so radauth_test
