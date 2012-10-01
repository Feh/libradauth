DEFAULT: libradauth.so radauth_test

ifdef DEBUG
DFLAGS = -DDEBUG -g
else
DGLAGS =
endif

SONAME = libradauth.so.0
FREERADIUS_CPPFLAGS = -I/usr/include/freeradius
FREERADIUS_LDFLAGS = -L/usr/lib/freeradius -rpath /usr/lib/freeradius -soname=$(SONAME)
FREERADIUS_LIBS = -lfreeradius-radius -lpthread -lc

radauth_test: radauth_test.c Makefile
	gcc -Wall $(DFLAGS) -L. -lradauth -o radauth_test radauth_test.c
libradauth.o: libradauth.c libradauth.h Makefile
	gcc -Wall $(DFLAGS) $(FREERADIUS_CPPFLAGS) -fPIC -c libradauth.c
libradauth.so: libradauth.o
	ld $(FREERADIUS_LDFLAGS) -shared -o $(SONAME) libradauth.o \
	    $(FREERADIUS_LIBS)
	ln -s $(SONAME) libradauth.so

clean:
	rm -f libradauth.o libradauth.so radauth_test $(SONAME)
