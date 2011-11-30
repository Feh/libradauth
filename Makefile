GCC = @echo 'CC  '$@;

radclient_test: radclient_test.c
	$(GCC)gcc -g -L/usr/lib/freeradius -Wl,-rpath,/usr/lib/freeradius -I/usr/include/freeradius -lpthread -lfreeradius-radius -o radclient_test radclient_test.c
