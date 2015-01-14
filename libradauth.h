#ifndef _LIBRADAUTH_H
#define _LIBRADAUTH_H

/* Indicates from where the callback function was called */
typedef enum {
	RAD_CB_VALUEPAIRS = 0, /* data: (VALUE_PAIR **) */
	RAD_CB_CREDENTIALS = 1, /* data: (RADIUS_PACKET *) */
	RAD_CB_REPLY = 2, /* data: (RADIUS_PACKET *) */
} rad_cb_action;

typedef enum {
	RAD_PACKET_AUTH,
	RAD_PACKET_ACCT,
} rad_packet_type;

void rad_auth_init(const char *userdict);
int rad_auth_simple(const char *username, const char *password,
		const char *config);
int rad_auth(const char *username, const char *password,
		int tries, const char *config, const char *userdict,
		const char *vps);
int rad_auth_r(const char *username, const char *password,
		int tries, const char *config, const char *vps,
		char *errmsg);
int rad_auth_cb(const char *username, const char *password,
		int tries, const char *config, const char *userdict,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg);
int rad_auth_cb_r(const char *username, const char *password,
		int tries, const char *config,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg, char *errmsg);
char *rad_auth_errstr(void);


int rad_acct(int tries, const char *config, const char *userdict,
		const char *vps);
int rad_acct_r(int tries, const char *config, const char *vps,
		char *errmsg);
int rad_acct_cb(int tries, const char *config, const char *userdict,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg);
int rad_acct_cb_r(int tries, const char *config,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg, char *errmsg);

#endif
