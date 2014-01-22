#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "libradauth.h"

struct autharg {
	char username[32], password[32], hostname[32];
	char *vp;
};

#define MAXTHREADS 32

static pthread_t threads[MAXTHREADS];

void *auth(void *p) {
	char errmsg[1024];
	int rc;
	struct autharg *arg;
	arg = (struct autharg *) p;
	rc = rad_auth_r(arg->username, arg->password, 3, "servers",
		arg->vp, errmsg);
	if(rc < 0)
		fprintf(stderr, "Cannot authenticate: %s\n", errmsg);
	else if(rc == 0)
		fprintf(stderr, "Successfully authenticated...\n");
	return NULL;
}

int main(int argc, char *argv[])
{
	int i;
	struct autharg arg;
	char vp[32 + 22];

	if(argc != 3) {
		fprintf(stdout, "<user> <pw>: ");
		fscanf(stdin, "%31s %31s", arg.username, arg.password);
	} else {
		strncpy(arg.username, argv[1], 31);
		strncpy(arg.password, argv[2], 31);
	}

	gethostname(arg.hostname, 31);
	snprintf(vp, sizeof(vp), "Calling-Station-ID = %s", arg.hostname);
	arg.vp = vp;

	rad_auth_init("dictionary.rfc2865");

	for(i = 0; i < MAXTHREADS; i++)
		pthread_create(&threads[i], NULL, auth, &arg);

	while(1) {
		for(i = 0; i < MAXTHREADS; i++) {
			pthread_join(threads[i], NULL);
			pthread_create(&threads[i], NULL, auth, &arg);
		}
	}

	return 0;
}

/* vim:set noet sw=8 ts=8: */
