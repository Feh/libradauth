GCC = @echo 'CC  '$@;

DEFAULT: libradauth.so radauth_test

ifdef DEBUG
DFLAGS = -DDEBUG -g
else
DGLAGS =
endif

FREERADIUS = -L/usr/lib/freeradius -Wl,-rpath,/usr/lib/freeradius \
	-I/usr/include/freeradius -lfreeradius-radius
LIBS = $(FREERADIUS) -lpthread

radauth_test: radauth_test.c
	$(GCC)gcc $(DFLAGS) $(LIBS) -Wl,-rpath,./ -L. -lradauth -o radauth_test radauth_test.c
libradauth.o: libradauth.c libradauth.h
	$(GCC)gcc $(DFLAGS) $(LIBS) -fPIC -c libradauth.c
libradauth.so: libradauth.o
	$(GCC)gcc -shared -o libradauth.so libradauth.o

clean:
	rm -f libradauth.o libradauth.so radauth_test
