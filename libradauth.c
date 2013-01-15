#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <limits.h>

#include <libradius.h>
#include <radpaths.h>
#include <conf.h>

#include "libradauth.h"
#include "libradauth-dict.h"

#define strlcpy(A,B,C) strncpy(A,B,C), *(A+(C)-1)='\0'
#define BUFSIZE 1024

#define LIBNAME "[libradauth] "
#define DEBUG_ENV_VAR "LIBRADAUTH_DEBUG"

static FILE *debugfp;
static int debug = 0;

#define debug(fmt, ...) \
	if(debug) fprintf(debugfp, LIBNAME fmt "\n", ##__VA_ARGS__)
#define error(fmt, ...) \
	{ snprintf(last_error, BUFSIZE, fmt, ##__VA_ARGS__); \
	debug("%s", last_error); }
#define debug_fr_error(what) \
	error(what ": %s%s", debug ? "ERROR: " : "", fr_strerror())
#define bail_fr_error(what) { debug_fr_error(what); rc = -1; goto done; }

struct rad_server;
struct rad_server {
	char name[64];
	char host[64];
	int port;
	int priority;
	int timeout;
	char bind[64];
	char secret[64];
	enum { UNKNOWN, PAP, CHAP, CUSTOM } method;
	struct rad_server *next;
};

typedef enum {
	RAD_CB_VALUEPAIRS = 0, /* data: (VALUE_PAIR *) */
} rad_cb_action;

static char last_error[BUFSIZE] = "";

char *rad_auth_errstr(void)
{
	return last_error;
}

static struct rad_server *parse_one_server(char *buf);
static struct rad_server *parse_servers(const char *config);
static void server_add_field(struct rad_server *s,
	const char *k, const char *v);
static int query_one_server(const char *username, const char *password,
	struct rad_server *server, int(*cb)(rad_cb_action, const void *, void *),
	const void *arg);
static int rad_auth_cb(const char *username, const char *password,
	int tries, const char *config, const char *userdict,
	int(*cb)(rad_cb_action, const void *, void *),
	const void *arg);
static int rad_cb_userparse(rad_cb_action action, const void *arg, void *data);
static struct rad_server *sort_servers(struct rad_server *list, int try);
static int cmp_prio_rand (const void *, const void *);
static void free_server_list(struct rad_server *head);
static int initialize_dictionary(char *dict, const char *userdict);
static int create_tmp_dict(char *dict);
static int ipaddr_from_server(struct in_addr *addr, const char *host);
static void setup_debugging(void);
static void clean_up_debugging(void);

static void setup_debugging(void)
{
	char *v;
	char errstr[1024];
	FILE *fp;

#ifdef DEBUG
	debug = 1;
#endif
	debugfp = stderr;

	if((v = getenv(DEBUG_ENV_VAR)) == NULL)
		return;

	debug = 1;
	if(!strcmp(v, "1"))
		return; /* log to stderr */
	if(!strcmp(v, "0")) {
		debug = 0;
		return;
	}

	/* try to log to the specified file */
	if((fp = fopen(v, "a")) != NULL) {
		debugfp = fp;
	} else {
		strerror_r(errno, errstr, 1024);
		debug("Warning: Cannot open '%s' for appending: %s; "
			"logging to stderr instead", v, errstr);
	}

	return;
}

static void clean_up_debugging(void)
{
	if(!debug)
		return;
	if(debugfp == stderr)
		return;
	fclose(debugfp);
	debugfp = stderr;
}

static struct rad_server *parse_servers(const char *config)
{
	FILE *fp;
	char buf[BUFSIZE];
	int n = 0;
	char *stm;
	char *brace;
	int s_len, s_size;
	int b_len = 0;
	struct rad_server *tmp, *cur, *head;

	head = NULL;

	if((fp = fopen(config, "r")) == NULL) {
		error("Failed to open config file '%s'!", config);
		return NULL;
	}

	stm = malloc(BUFSIZE * sizeof(char));
	if(stm == 0)
		return NULL;
	s_size = BUFSIZE;

	*stm = '\0';
	s_len = 0;
	while(fgets(buf, BUFSIZE-1, fp) != NULL) {
		n++;
		b_len = strlen(buf);

		/* skip comments and empty lines */
		if(buf[0] == '\n' || buf[0] == '#')
			continue;

		if(s_len + b_len + 1 > s_size) {
			char *tmp;

			debug("Resizing buffer to make the statement fit");
			s_size += BUFSIZE;
			tmp = realloc(stm, s_size);
			if(!tmp) {
				free(stm);
				return NULL;
			}
			stm = tmp;
		}

		brace = strrchr(buf, '}');
		if(brace && (brace == buf ||
				*(brace-1) == ' ' || *(brace-1) == '\t')) {
			*(brace+1) = '\0'; /* statement terminated */
			strncat(stm, buf, b_len);
			s_len += buf - brace + 1;
		} else {
			strncat(stm, buf, b_len);
			s_len += b_len;
			continue; /* next line! */
		}

		tmp = parse_one_server(stm);
		s_len = 0;
		*stm = '\0';

		if(!tmp)
			continue;

		if(!head)
			cur = head = tmp;
		else {
			cur->next = tmp;
			cur = tmp;
		}
		debug("successfully added server '%s': %s:%d "
			"(prio %d, timeout %dms, method %s)",
			cur->name, cur->host, cur->port, cur->priority,
			cur->timeout, cur->method == CHAP ? "CHAP" :
				(cur->method == PAP ? "PAP" : "CUSTOM"));
	}

	if(s_len > 0) {
		debug("reached EOF, could not find closing '}'!");
		debug("    (statement will be ignored)");
	}

	free(stm);
	fclose(fp);

	return head;
}

static struct rad_server *sort_servers(struct rad_server *list, int try)
{
	int i, n;
	struct rad_server *head, *tmp;
	struct rad_server **servers;

	for(n = 0, tmp = list; tmp; tmp = tmp->next)
		n++;

	servers = malloc(n * sizeof(struct rad_server *));
	if(!servers)
		return NULL;

	for(i = 0, tmp = list; i < n; i++, tmp = tmp->next)
		servers[i] = tmp;

	srand(time(NULL) + 0xF00 * try);
	qsort(servers, n, sizeof(struct rad_server *), cmp_prio_rand);

	/* reconstruct the list */
	head = servers[0];
	for(i = 1, tmp = head; i < n; i++, tmp = tmp->next)
		tmp->next = servers[i];
	tmp->next = NULL; /* last entry */

	/* debugging */
	tmp = head;
	debug("Servers will be tried in this order: ");
	debug("   prio name = host:port");
	do {
		debug("%7d %s = %s:%d", tmp->priority,
			tmp->name, tmp->host, tmp->port);
	} while ((tmp = tmp->next));

	free(servers);

	return head;
}

static int cmp_prio_rand (const void *a, const void *b)
{
	struct rad_server *r, *s;
	r = * (struct rad_server * const *) a;
	s = * (struct rad_server * const *) b;

	if(r->priority < s->priority)
		return 1;
	if(r->priority > s->priority)
		return -1;
	/* same priority - pick a random one :-) */
	return (rand() % 2 ? -1 : 1);
}

static struct rad_server *parse_one_server(char *buf)
{
	struct rad_server *s;
	const char delim[4] = " \t\n";
	char *t, *v, *rest;
	char token[64];

	s = malloc(sizeof(*s));
	if(!s) {
		free(s);
		return NULL;
	}

	if(!(t = strtok_r(buf, delim, &rest))) {
		free(s);
		return NULL;
	}
	strlcpy(s->name, t, 64);

	/* fill with defaults */
	*(s->host) = '\0';
	*(s->secret) = '\0';
	s->port = 1812;
	s->priority = 0;
	s->timeout = 1000; /* 1 second */
	s->method = CHAP;
	strcpy(s->bind, "0.0.0.0");

	if(!(t = strtok_r(NULL, delim, &rest)) || *t != '{') {
		debug("could not find '{' after statement name!");
		free(s);
		return NULL;
	}

	while((t = strtok_r(NULL, delim, &rest)) && *t != '}') {
		strlcpy(token, t, 64);
		if((v = strtok_r(NULL, delim, &rest)))
			server_add_field(s, token, v);
	}

	if(!*(s->host) || s->method == UNKNOWN) {
		debug("%s: At least a 'host' is needed!", s->name);
		free(s);
		return NULL;
	}

	s->next = NULL;
	return s;
}

static void server_add_field(struct rad_server *s, const char *k, const char *v)
{
	if(!strcmp(k, "host"))
		strlcpy(s->host, v, sizeof(s->host));
	else if(!strcmp(k, "bind"))
		strlcpy(s->bind, v, sizeof(s->bind));
	else if(!strcmp(k, "secret"))
		strlcpy(s->secret, v, sizeof(s->secret));
	else if(!strcmp(k, "port"))
		s->port = atoi(v);
	else if(!strcmp(k, "priority"))
		s->priority = atoi(v);
	else if(!strcmp(k, "timeout"))
		s->timeout = atoi(v);
	else if(!strcmp(k, "method")) {
		if(!strcasecmp(v, "CHAP"))
			s->method = CHAP;
		else if(!strcasecmp(v, "PAP"))
			s->method = PAP;
		else if(!strcasecmp(v, "CUSTOM"))
			s->method = CUSTOM;
		else
			s->method = UNKNOWN;
	} else {
		debug("%s: wrong or unknown key: %s = %s", s->name, k, v);
	}
}

static void free_server_list(struct rad_server *head)
{
	struct rad_server *cur, *tmp;
	cur = head;
	do {
		tmp = cur->next;
		free(cur);
		cur = tmp;
	} while(cur);
}

static int initialize_dictionary(char *dict, const char *userdict)
{
	char *slash;
	int rc;

	if(userdict) {
		debug("Initializing user dictionary '%s'", userdict);
		strlcpy(dict, userdict, PATH_MAX-1);
	} else {
		debug("Initializing temporary dictionary at '%s'...", P_tmpdir);
		if(create_tmp_dict(dict) == -1)
			return -1;
		debug("Done, it's at '%s'", dict);
	}

	/* actually initialize */
	slash = strrchr(dict, '/');
	if(slash) {
		*slash = '\0';
		rc = dict_init(dict, slash+1);
		*slash = '/';
	} else {
		rc = dict_init(".", dict);
	}

	return rc;
}

static int create_tmp_dict(char *dict)
{
	FILE *fp;
	char errstr[1024];

	sprintf(dict, "%s/dictionary.XXXXXX", P_tmpdir);
	if(mkstemp(dict) == -1) {
		strerror_r(errno, errstr, 1024);
		error("cannot create tempfile for dictionary '%s': %s", dict, errstr);
		return -1;
	}
	if(!(fp = fopen(dict, "w"))) {
		strerror_r(errno, errstr, 1024);
		error("cannot open temporary dictionary '%s': %s", dict, errstr);
		return -1;
	}
	fwrite(dictionary_rfc2865, strlen(dictionary_rfc2865),
		sizeof (char), fp);
	fclose(fp);

	return 0;
}

static int ipaddr_from_server(struct in_addr *addr, const char *host)
{
	struct hostent *res;

	if(!(res = gethostbyname(host))) {
		debug("  -> Failed to resolve host '%s'.", host);
		return 0;
	}

	addr->s_addr = ((struct in_addr*) res->h_addr_list[0])->s_addr;
	debug("  -> resolved '%s' to '%s'", host, inet_ntoa(*addr));
	return 1;
}

static int query_one_server(const char *username, const char *password,
		struct rad_server *server,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg)
{
	struct timeval tv;
	volatile int max_fd;
	fd_set set;
	struct sockaddr_in src;
	socklen_t src_size = sizeof(src);
	int rc = -2;

	fr_ipaddr_t client;
	fr_packet_list_t *pl = 0;
	VALUE_PAIR *vp;
	RADIUS_PACKET *request = 0, *reply = 0;

	request = rad_alloc(1);
	if(!request)
		bail_fr_error("rad_alloc");

	request->code = PW_AUTHENTICATION_REQUEST;

	request->dst_ipaddr.af = AF_INET;
	request->dst_port = server->port;
	if(!ipaddr_from_server(
		&(request->dst_ipaddr.ipaddr.ip4addr), server->host))
		goto done;

	memset(&client, 0, sizeof(client));
	client.af = AF_INET;
	if(!ipaddr_from_server(&(client.ipaddr.ip4addr), server->bind))
		goto done;

	/* int sockfd = fr_socket(&request->dst_ipaddr, 0); */
	int sockfd = fr_socket(&client, 0);
	if(!sockfd)
		bail_fr_error("fr_socket");
	request->sockfd = -1;
	request->code = PW_AUTHENTICATION_REQUEST;

	if(!(pl = fr_packet_list_create(1)))
		bail_fr_error("fr_packet_list_create");

	if(!fr_packet_list_socket_add(pl, sockfd))
		bail_fr_error("fr_packet_list_socket_add");

	if(fr_packet_list_id_alloc(pl, request) < 0)
		bail_fr_error("fr_packet_list_id_alloc");

	/* construct value pairs */
	if(!(vp = pairmake("User-Name", username, 0)))
		bail_fr_error("pairmake");
	pairadd(&request->vps, vp);

	if(server->method == PAP) {
		debug("  -> Using PAP-scrambled passwords");
		/* encryption of the packet will happen *automatically* just
		 * before sending the packet via make_passwd() */
		if(!(vp = pairmake("User-Password", password, 0)))
			bail_fr_error("pairmake");
		vp->flags.encrypt = FLAG_ENCRYPT_USER_PASSWORD;
		pairadd(&request->vps, vp);
	} else if(server->method == CHAP) {
		debug("  -> Using CHAP-scrambled passwords");
		if(!(vp = pairmake("CHAP-Password", password, 0)))
			bail_fr_error("pairmake");
		strlcpy(vp->vp_strvalue, password,
			sizeof(vp->vp_strvalue));
		vp->length = strlen(vp->vp_strvalue);
		rad_chap_encode(request, vp->vp_octets, request->id, vp);
		vp->length = 17;
		pairadd(&request->vps, vp);
	} else if(server->method == CUSTOM) {
		debug("  -> Using custom authentication method");
	}

	memset(&src, 0, sizeof(src));
	if(fr_ipaddr2sockaddr(&(request->dst_ipaddr), server->port,
		(struct sockaddr_storage *) &src, &src_size)) {
		/* This will "connect" the socket to the remote side. Since we
		 * use UDP, this will just set the "default destination" for
		 * packets. We need this call in order to find out our source
		 * IP address. */
		connect(sockfd, (struct sockaddr *) &src, src_size);
	}
	memset(&src, 0, sizeof(src));
	if(getsockname(sockfd, (struct sockaddr *) &src, &src_size) < 0) {
		error("getsockname: cannot resolve own socket address.");
		rc = -1;
		goto done;
	}
	if(!(vp = pairmake("NAS-IP-Address", "0.0.0.0", 0))) /* dummy */
		bail_fr_error("pairmake");
	vp->vp_ipaddr = src.sin_addr.s_addr; /* real address */
	pairadd(&request->vps, vp);
	if(!(vp = pairmake("NAS-Port", "10", 0)))
		bail_fr_error("pairmake");
	pairadd(&request->vps, vp);

	/* callback function */
	if(cb && cb(RAD_CB_VALUEPAIRS, arg, (void *)request->vps) != 0) {
		debug("  -> WARNING: Callback returned nonzero exit status!");
	}

	if(server->method == CUSTOM && !pairfind(request->vps, PW_STATE)) {
		debug("WARNING: You MUST use a 'State' attribute with your "
			"custom authentication mechanism. See RFC 2865, 4.1.");
	}

	debug("  -> Sending packet via %s:%d...",
		inet_ntoa(src.sin_addr), ntohs(src.sin_port));

	if(rad_send(request, NULL, server->secret) == -1)
		bail_fr_error("rad_send");

	/* And wait for reply, timing out as necessary */
	FD_ZERO(&set);

	max_fd = fr_packet_list_fd_set(pl, &set);
	if (max_fd < 0)
		bail_fr_error("fr_packet_list_fd_set");

	/* wait a configured time (default: 1.0s) */
	tv.tv_sec  = server->timeout / 1000;
	tv.tv_usec = 1000 * (server->timeout % 1000);

	if (select(max_fd, &set, NULL, NULL, &tv) <= 0) {
		debug("  -> TIMEOUT: no packet received in %dms!",
			server->timeout);
		rc = -2;
		goto done;
	}

	reply = fr_packet_list_recv(pl, &set);
	if (!reply)
		bail_fr_error("received bad packet")

	if (rad_verify(reply, request, server->secret) < 0)
		bail_fr_error("rad_verify");

	fr_packet_list_yank(pl, request);

	if (rad_decode(reply, request, server->secret) != 0)
		bail_fr_error("rad_decode");

	if(reply->code == PW_AUTHENTICATION_ACK) {
		rc = 0;
		debug("  -> ACK: Authentication was successful.");
	}

	if(reply->code == PW_AUTHENTICATION_REJECT) {
		rc = 1;
		debug("  -> REJECT: Authentication was not successful.");
	}

	done:
	if(request)
		rad_free(&request);
	if(reply)
		rad_free(&reply);
	if(pl)
		fr_packet_list_free(pl);

	return rc;
}

int rad_auth_simple(const char *username, const char *password,
		const char *config)
{
	return rad_auth(username, password, 3, config, NULL, NULL);
}

int rad_auth(const char *username, const char *password,
		int tries, const char *config, const char *userdict,
		const char *vps)
{
	return rad_auth_cb(username, password, tries, config, userdict,
				rad_cb_userparse, (void *)vps);
}

static int rad_cb_userparse(rad_cb_action action, const void *arg, void *data)
{
	const char *userpairs;
	VALUE_PAIR *vp, *vps;
	char buf[BUFSIZE];

	if(action != RAD_CB_VALUEPAIRS)
		return 0;

	userpairs = (const char *)arg;
	vps = (VALUE_PAIR *)data;

	if(userparse(userpairs, &vps) == T_OP_INVALID)
		debug("WARNING: userparse() could not parse all attributes!");
	for(vp = vps; vp; vp = vp->next) {
		if(vp->attribute == PW_USER_NAME ||
		   vp->attribute == PW_USER_PASSWORD ||
		   vp->attribute == PW_CHAP_PASSWORD ||
		   vp->attribute == PW_NAS_IP_ADDRESS ||
		   vp->attribute == PW_NAS_PORT)
			continue;
		vp_prints(buf, BUFSIZE, vp);
		debug("  -> Added attribute: %s", buf);
	}

	return 0;
}

int rad_auth_cb(const char *username, const char *password,
		int tries, const char *config, const char *userdict,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg)
{
	struct rad_server *serverlist = 0, *server = 0;
	char dict[PATH_MAX];
	int rc = -1;
	int try;

	setup_debugging();

	if(initialize_dictionary(dict, userdict) < 0)
		bail_fr_error("initialize_dictionary");

	debug("parsing servers from config file '%s'", config);
	serverlist = parse_servers(config);
	if(!serverlist) {
		error("Could not parse server config '%s', cannot continue.", config);
		rc = -1;
		goto done;
	}

	for(try = 1; try <= tries; try++) {
		debug("ATTEMPT #%d of %d", try, tries);
		server = serverlist = sort_servers(serverlist, try);
		do {
			debug("Querying server: %s:%d", server->name, server->port);
			rc = query_one_server(username, password, server, cb, arg);
			if(rc >= 0)
				goto done;
		} while((server = server->next) != NULL);
		debug("FAILED to reach any of the servers at try #%d/%d. %s",
			try, tries, try == tries ? "Giving up." : "Trying again...");
		if(try == tries && rc == -2)
			snprintf(last_error, BUFSIZE, "Timeout: No authentication "
				"servers could be reached after %d tries.", try);
	}

	done:
	if(serverlist)
		free_server_list(serverlist);
	if(!userdict) {
		debug("unlinking temporary dictionary '%s'...", dict);
		unlink(dict);
	}

	clean_up_debugging();

	return rc;
}

/* vim:set noet sw=8 ts=8: */
