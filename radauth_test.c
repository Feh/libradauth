#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "libradauth.h"

int main(int argc, char *argv[])
{
	int rc;
	char username[32], password[32], hostname[32];
	char vp[32 + 22];
	const char *my_dict[2] = { ".", "dictionary" };

	if(argc != 3) {
		fprintf(stdout, "<user> <pw>: ");
		fscanf(stdin, "%31s %31s", username, password);
	} else {
		strncpy(username, argv[1], 31);
		strncpy(password, argv[2], 31);
	}

	gethostname(hostname, 31);
	snprintf(vp, sizeof(vp), "Calling-Station-ID = %s", hostname);

	rc = rad_auth(username, password, 3, "./servers",
		my_dict, vp);
	if(rc == -1)
		fprintf(stderr, "Cannot authenticate: %s\n",
				rad_auth_errstr());
	if(rc == -2)
		fprintf(stderr, "A generic error happened, "
			"no servers could be reached.\n");
	return rc;
}

/* vim:set noet sw=8 ts=8: */
