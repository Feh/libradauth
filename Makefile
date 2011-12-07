GCC = @echo 'CC  '$@;

DEFAULT: libradauth.so radauth_test

radauth_test:
	$(GCC)gcc -DDEBUG -L/usr/lib/freeradius -Wl,-rpath,/usr/lib/freeradius -I/usr/include/freeradius -lpthread -lfreeradius-radius -Wl,-rpath,./ -L. -lradauth -o radauth_test radauth_test.c
libradauth.o:
	$(GCC)gcc -DDEBUG -L/usr/lib/freeradius -Wl,-rpath,/usr/lib/freeradius -I/usr/include/freeradius -lpthread -lfreeradius-radius -fPIC -c libradauth.c
libradauth.so: libradauth.o
	$(GCC)gcc -shared -o libradauth.so libradauth.o

clean:
	rm -f libradauth.o libradauth.so radauth_test
