#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include "libradauth.h"

struct autharg {
	char username[32], password[32], hostname[32];
	char *vp;
};

#define MAXTHREADS 32

static int running = 1;
static struct sigaction sigint;
static pthread_mutex_t wait_sigint = PTHREAD_MUTEX_INITIALIZER;

static pthread_t threads[MAXTHREADS];

/* signal handler */
void sigint_called() {
	pthread_mutex_unlock(&wait_sigint);
}

void *auth(void *p) {
	char errmsg[1024];
	int rc;
	struct autharg *arg;
	arg = (struct autharg *) p;
	while(running) {
		rc = rad_auth_r(arg->username, arg->password, 3, "servers",
			arg->vp, errmsg);
		if(rc < 0)
			fprintf(stderr, "Cannot authenticate: %s\n", errmsg);
		else if(rc >= 0)
			fprintf(stderr, ".");
	}
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

	/* install signal handler that will unlock wait_sigint */
	pthread_mutex_lock(&wait_sigint);
	sigint.sa_handler = sigint_called;
	sigaction(SIGINT, &sigint, NULL);

	/* dispatch threads */
	for(i = 0; i < MAXTHREADS; i++)
		pthread_create(&threads[i], NULL, auth, &arg);

	/* waiting for sigint */
	pthread_mutex_lock(&wait_sigint);
	running = 0;
	fprintf(stderr, "\nCtrl-C caught, waiting for threads to finish...\n");

	for(i = 0; i < MAXTHREADS; i++)
		pthread_join(threads[i], NULL);

	fprintf(stderr, "\nAll done. Exiting.\n");

	return 0;
}

/* vim:set noet sw=8 ts=8: */
