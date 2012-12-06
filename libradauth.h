#ifndef _LIBRADAUTH_H
#define _LIBRADAUTH_H
int rad_auth_simple(const char *username, const char *password,
		const char *config);
int rad_auth(const char *username, const char *password,
		int tries, const char *config, const char *userdict,
		const char *vps);
char *rad_auth_errstr(void);
#endif
