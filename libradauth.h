#ifndef _LIBRADAUTH_H
#define _LIBRADAUTH_H
int rad_auth(const char *username, const char *password,
        int retries, const char *config, const char *dict[2]);
char *rad_auth_errstr(void);
#endif
