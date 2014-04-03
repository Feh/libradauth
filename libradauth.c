#include <errno.h>
#include <netdb.h>
#include <limits.h>
#include <poll.h>
#include <assert.h>

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
	{ snprintf(errmsg, BUFSIZE, fmt, ##__VA_ARGS__); \
	debug("%s", errmsg); }
#define debug_fr_error(what) \
	error(what ": %s%s", debug ? "ERROR: " : "", fr_strerror())
#define bail_fr_error(what) { debug_fr_error(what); rc = -1; goto done; }

struct rad_server;
struct rad_server {
	char name[BUFSIZE];
	char host[BUFSIZE];
	int port;
	int acctport;
	int priority;
	int timeout;
	char bind[BUFSIZE];
	char secret[BUFSIZE];
	enum { UNKNOWN, PAP, CHAP, CUSTOM } method;
	struct rad_server *next;
};

struct rad_credentials {
	char username[BUFSIZE];
	char password[BUFSIZE];
	struct rad_server *server;
};

struct auth_args {
	char const *username;
	char const *password;
	int(*cb)(rad_cb_action, const void *, void *);
	void const *arg;
};

struct acct_args {
	int(*cb)(rad_cb_action, const void *, void *);
	void const *arg;
};

/* A list of callback functions and assigned arguments */
struct rad_cb_list;
struct rad_cb_list {
	int(*f)(rad_cb_action, const void *, void *);
	void const *arg;
	struct rad_cb_list *next;
};

/* Not re-entrant library functions use this. */
static char last_error[BUFSIZE] = "";
static char temp_dict[PATH_MAX];

char *rad_auth_errstr(void)
{
	return last_error;
}

static struct rad_server *parse_one_server(char *buf);
static struct rad_server *parse_servers(const char *config, char *errmsg);
static void server_add_field(struct rad_server *s,
	const char *k, const char *v);
static int rad_cb_userparse(rad_cb_action action, const void *arg, void *data);
static struct rad_server *sort_servers(struct rad_server *list, int try);
static int cmp_prio_rand (const void *, const void *);
static void free_server_list(struct rad_server *head);
static int initialize_dictionary(char *dict, const char *userdict);
static int create_tmp_dict(char *dict);
static int ipaddr_from_server(struct in_addr *addr, const char *host);
static void setup_debugging(void);
static void clean_up_debugging(void);

void rad_auth_init(const char *userdict) {
	setup_debugging();

	if(initialize_dictionary(temp_dict, userdict) < 0)
		fprintf(stderr, "initialize_dictionary");
}

static void rad_auth_cleanup() {
	if(*temp_dict) {
		debug("unlinking temporary dictionary '%s'...", temp_dict);
		unlink(temp_dict);
	}

	clean_up_debugging();
}

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

static struct rad_server *parse_servers(const char *config, char *errmsg)
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
			"(prio %d, timeout %dms, method %s, acctport %d)",
			cur->name, cur->host, cur->port, cur->priority,
			cur->timeout, cur->method == CHAP ? "CHAP" :
				(cur->method == PAP ? "PAP" : "CUSTOM"),
			cur->acctport);
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
	debug("   prio name (host)");
	do {
		debug("%7d %s (%s)", tmp->priority, tmp->name, tmp->host);
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
	char token[BUFSIZE];

	s = malloc(sizeof(*s));
	if(!s) {
		free(s);
		return NULL;
	}

	if(!(t = strtok_r(buf, delim, &rest))) {
		free(s);
		return NULL;
	}
	strlcpy(s->name, t, sizeof(s->name));

	/* fill with defaults */
	*(s->host) = '\0';
	*(s->secret) = '\0';
	s->port = 1812;
	s->acctport = 1813;
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
		strlcpy(token, t, sizeof(token));
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
	else if(!strcmp(k, "acctport"))
		s->acctport = atoi(v);
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

	if(userdict)
		*dict = '\0';

	return rc;
}

static int create_tmp_dict(char *dict)
{
	FILE *fp;
	char errstr[1024];

	sprintf(dict, "%s/dictionary.XXXXXX", P_tmpdir);
	if(mkstemp(dict) == -1) {
		strerror_r(errno, errstr, 1024);
		debug("cannot create tempfile for dictionary '%s': %s", dict, errstr);
		return -1;
	}
	if(!(fp = fopen(dict, "w"))) {
		strerror_r(errno, errstr, 1024);
		debug("cannot open temporary dictionary '%s': %s", dict, errstr);
		return -1;
	}
	fwrite(dictionary_rfc2865, strlen(dictionary_rfc2865),
		sizeof (char), fp);
	fclose(fp);

	return 0;
}

static int ipaddr_from_server(struct in_addr *addr, const char *host)
{
	int code;
	struct addrinfo *res, hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; /* Only allow IPv4 for now */
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;

	if((code = getaddrinfo(host, NULL, &hints, &res)) < 0 || res == NULL) {
		debug("  -> Failed to resolve host '%s': %s", host,
			gai_strerror(code));
		return 0;
	}
	addr->s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(res);

	debug("  -> resolved '%s' to '%s'", host, inet_ntoa(*addr));
	return 1;
}

static int send_recv(rad_packet_type type,
		struct rad_server *server,
		struct rad_cb_list *cb_head,
		char *errmsg)
{
	int sockfd = -1, max_fd, port;
	fd_set set;
	struct pollfd pset[1];
	struct sockaddr_storage src;
	struct sockaddr_in *src_in;
	socklen_t src_size = sizeof(src);
	int rc = -2;
	struct rad_cb_list *cb;

	fr_ipaddr_t client;
	fr_packet_list_t *pl = 0;
	VALUE_PAIR *vp;
	RADIUS_PACKET *request = 0, *reply = 0;

	request = rad_alloc(1);
	if(!request)
		bail_fr_error("rad_alloc");

	switch(type) {
	case RAD_PACKET_AUTH:
		request->code = PW_AUTHENTICATION_REQUEST;
		port = server->port;
		break;
	case RAD_PACKET_ACCT:
		request->code = PW_ACCOUNTING_REQUEST;
		port = server->acctport;
		break;
	default:
		error("send_recv: Unknow packet type, cannot send");
		goto done;
	}

	debug("Querying server: %s (%s:%d)", server->name, server->host, port);

	request->dst_ipaddr.af = AF_INET;
	request->dst_port = port;
	if(!ipaddr_from_server(
		&(request->dst_ipaddr.ipaddr.ip4addr), server->host))
		goto done;

	memset(&client, 0, sizeof(client));
	client.af = AF_INET;
	if(!ipaddr_from_server(&(client.ipaddr.ip4addr), server->bind))
		goto done;

	/* int sockfd = fr_socket(&request->dst_ipaddr, 0); */
	sockfd = fr_socket(&client, 0);
	if(!sockfd)
		bail_fr_error("fr_socket");

	/* An fd_set can only hold fds up to the *value* of FD_SETSIZE (usually
	 * 1024). So we assert here that we do not reach this value. It is
	 * better to die here, than to get a slow, creeping memory corruption
	 * from FD_SET(). */
	if(sockfd >= FD_SETSIZE) {
		error("FATAL: Not safe to store sockfd = %d in an FD_SET "
			"(FD_SETSIZE = %d). Cannot continue!", sockfd, FD_SETSIZE);
		rc = -1;
		goto done;
	}

	request->sockfd = -1;

	if(!(pl = fr_packet_list_create(1)))
		bail_fr_error("fr_packet_list_create");

	if(!fr_packet_list_socket_add(pl, sockfd))
		bail_fr_error("fr_packet_list_socket_add");

	if(fr_packet_list_id_alloc(pl, request) < 0)
		bail_fr_error("fr_packet_list_id_alloc");

	/* callback function */
	for(cb = cb_head; cb; cb = cb->next) {
		if(cb->f && cb->f(RAD_CB_CREDENTIALS, cb->arg, (void *)request) != 0) {
			debug("  -> WARNING: Credentials callback returned "
				"nonzero exit status!");
		}
	}

	memset(&src, 0, sizeof(src));
	src_in = (struct sockaddr_in *) &src;
	if(fr_ipaddr2sockaddr(&(request->dst_ipaddr), port, &src, &src_size)) {
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

	if(type == RAD_PACKET_AUTH) {
		if(!(vp = pairmake("NAS-IP-Address", "0.0.0.0", 0))) /* dummy */
			bail_fr_error("pairmake");
		vp->vp_ipaddr = src_in->sin_addr.s_addr; /* real address */
		pairadd(&request->vps, vp);
		if(!(vp = pairmake("NAS-Port", "10", 0)))
			bail_fr_error("pairmake");
		pairadd(&request->vps, vp);
	}

	/* callback function */
	for(cb = cb_head; cb; cb = cb->next) {
		if(cb->f && cb->f(RAD_CB_VALUEPAIRS, cb->arg, (void *)&request->vps) != 0) {
			debug("  -> WARNING: Valuepair callback "
				"returned nonzero exit status!");
		}
	}

	if(type == RAD_PACKET_AUTH && server->method == CUSTOM &&
		!pairfind(request->vps, PW_STATE)) {
		debug("WARNING: You MUST use a 'State' attribute with your "
			"custom authentication mechanism. See RFC 2865, 4.1.");
	}

	debug("  -> Sending packet via %s:%d...",
		inet_ntoa(src_in->sin_addr), ntohs(src_in->sin_port));

	if(rad_send(request, NULL, server->secret) == -1)
		bail_fr_error("rad_send");

	/* We'll use poll(), but need the same information in an fd_set for
	 * fr_packet_list_recv() further down */
	FD_ZERO(&set);
	FD_SET(sockfd, &set);
	max_fd = sockfd + 1;

	memset(&pset, 0, sizeof(pset));
	pset[0].fd = sockfd;
	pset[0].events = POLLIN;
	if (poll(pset, sizeof(pset)/sizeof(pset[0]), server->timeout) <= 0) {
		debug("  -> TIMEOUT: no packet received in %dms!",
			server->timeout);
		rc = -2;
		goto done;
	}

	reply = fr_packet_list_recv(pl, &set);
	if(!reply)
		bail_fr_error("received bad packet");

	if (rad_verify(reply, request, server->secret) < 0)
		bail_fr_error("rad_verify");

	fr_packet_list_yank(pl, request);
	fr_packet_list_id_free(pl, request);

	if (rad_decode(reply, request, server->secret) != 0)
		bail_fr_error("rad_decode");

	switch(reply->code) {
	case PW_AUTHENTICATION_ACK:
		rc = 0;
		debug("  -> ACK: Authentication was successful.");
		break;
	case PW_AUTHENTICATION_REJECT:
		rc = 1;
		debug("  -> REJECT: Authentication was not successful.");
		break;
	case PW_ACCOUNTING_RESPONSE:
		rc = 0;
		debug("  -> ACK: Accounting packet arrived successfully.");
		break;
	default:
		debug("  -> UNKNOWN: Received a reply that I don't know");
	}

	done:
	if(request)
		rad_free(&request);
	if(reply)
		rad_free(&reply);
	if(pl)
		fr_packet_list_free(pl);
	if(sockfd > 0)
		close(sockfd);

	return rc;
}

static int rad_cb_credentials(rad_cb_action action,
				const void *arg, void *data)
{
	struct rad_credentials *cred;
	RADIUS_PACKET *request;
	VALUE_PAIR *vp;


	if(action != RAD_CB_CREDENTIALS)
		return 0;
	if(arg == NULL || data == NULL)
		return 0;

	request = (RADIUS_PACKET *)data;
	cred = (struct rad_credentials *)arg;

	debug("  -> Adding credentials");

	/* construct value pairs */
	if(!(vp = pairmake("User-Name", cred->username, 0)))
		return 1;
	pairadd(&request->vps, vp);

	if(cred->server->method == PAP) {
		debug("  -> Using PAP-scrambled passwords");
		/* encryption of the packet will happen *automatically* just
		 * before sending the packet via make_passwd() */
		if(!(vp = pairmake("User-Password", cred->password, 0)))
			return 1;
		vp->flags.encrypt = FLAG_ENCRYPT_USER_PASSWORD;
		pairadd(&request->vps, vp);
	} else if(cred->server->method == CHAP) {
		debug("  -> Using CHAP-scrambled passwords");
		if(!(vp = pairmake("CHAP-Password", "", 0)))
			return 1;
		strlcpy(vp->vp_strvalue, cred->password,
			sizeof(vp->vp_strvalue));
		vp->length = strlen(vp->vp_strvalue);
		rad_chap_encode(request, vp->vp_octets, request->id, vp);
		vp->length = 17;
		pairadd(&request->vps, vp);
	} else if(cred->server->method == CUSTOM) {
		debug("  -> Using custom authentication method");
	}

	return 0;
}

static int try_auth_one_server(struct rad_server *server,
				void *ap, char *errmsg)
{
	struct auth_args *args;
	struct rad_credentials cred;
	struct rad_cb_list *cb_head;
	struct rad_cb_list cb_cred, cb_userdefined;

	args = (struct auth_args *)ap;

	/* We construct a list of callback functions. First, we add
	 * credentials. Next, we add the user-defined callback function. */
	cb_head = &cb_cred;

	strlcpy(cred.username, args->username, sizeof(cred.username));
	strlcpy(cred.password, args->password, sizeof(cred.password));
	cred.server = server;

	cb_cred.f = rad_cb_credentials;
	cb_cred.arg = (void *) &cred;
	cb_cred.next = &cb_userdefined;

	cb_userdefined.f = args->cb;
	cb_userdefined.arg = args->arg;
	cb_userdefined.next = NULL;

	return send_recv(RAD_PACKET_AUTH, server, cb_head, errmsg);
}

static int try_acct_one_server(struct rad_server *server,
				void *ap, char *errmsg)
{
	struct acct_args *args;
	struct rad_cb_list *cb_head;
	struct rad_cb_list cb_userdefined;

	args = (struct acct_args *)ap;

	/* We construct a list of callback functions.
	 * For now it only includes the userdefined (e.g. rad_cb_userparse) */
	cb_head = &cb_userdefined;

	cb_userdefined.f = args->cb;
	cb_userdefined.arg = args->arg;
	cb_userdefined.next = NULL;

	return send_recv(RAD_PACKET_ACCT, server, cb_head, errmsg);
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

int rad_acct(int tries, const char *config, const char *userdict,
		const char *vps)
{
	return rad_acct_cb(tries, config, userdict,
				rad_cb_userparse, (void *)vps);
}

int rad_auth_r(const char *username, const char *password,
		int tries, const char *config, const char *vps,
		char *errmsg)
{
	return rad_auth_cb_r(username, password, tries, config,
				rad_cb_userparse, (void *)vps, errmsg);
}

int rad_acct_r(int tries, const char *config, const char *vps,
		char *errmsg)
{
	return rad_acct_cb_r(tries, config,
				rad_cb_userparse, (void *)vps, errmsg);
}

static int rad_cb_userparse(rad_cb_action action, const void *arg, void *data)
{
	const char *userpairs;
	VALUE_PAIR *vp;
	VALUE_PAIR **vps;
	char buf[BUFSIZE];

	if(action != RAD_CB_VALUEPAIRS)
		return 0;

	userpairs = (const char *)arg;
	vps = (VALUE_PAIR **)data;

	/* do we have value pairs to add? */
	if(arg == NULL)
		return 0;

	if(userparse(userpairs, vps) == T_OP_INVALID)
		debug("WARNING: userparse() could not parse all attributes!");
	for(vp = *vps; vp; vp = vp->next) {
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
	int rc;

	rad_auth_init(userdict);
	rc = rad_auth_cb_r(username, password, tries, config, cb, arg, last_error);
	rad_auth_cleanup();

	return rc;
}

int rad_acct_cb(int tries, const char *config, const char *userdict,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg)
{
	int rc;

	rad_auth_init(userdict);
	rc = rad_acct_cb_r(tries, config, cb, arg, last_error);
	rad_auth_cleanup();

	return rc;
}

int loop_servers(const char *config, int tries,
	int (*f)(struct rad_server *, void *, char *),
	void *arg, char *errmsg)
{
	struct rad_server *serverlist = 0, *server = 0;
	int rc = -1;
	int try;

	errmsg[0] = '\0';

	debug("parsing servers from config file '%s'", config);
	serverlist = parse_servers(config, errmsg);
	if(!serverlist) {
		error("Could not parse server config '%s', cannot continue.", config);
		rc = -1;
		goto done;
	}

	for(try = 1; try <= tries; try++) {
		debug("ATTEMPT #%d of %d", try, tries);
		server = serverlist = sort_servers(serverlist, try);
		do {
			rc = f(server, arg, errmsg);
			if(rc >= 0)
				goto done;
		} while((server = server->next) != NULL);
		debug("FAILED to reach any of the servers at try #%d/%d. %s",
			try, tries, try == tries ? "Giving up." : "Trying again...");
		if(try == tries && rc == -2)
			snprintf(errmsg, BUFSIZE, "Timeout: No authentication "
				"servers could be reached after %d tries.", try);
	}

	done:
	if(serverlist)
		free_server_list(serverlist);

	return rc;
}

int rad_auth_cb_r(const char *username, const char *password,
		int tries, const char *config,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg, char *errmsg)
{
	struct auth_args a;
	a.username = username;
	a.password = password;
	a.cb = cb;
	a.arg = arg;
	return loop_servers(config, tries, try_auth_one_server, (void *)&a, errmsg);
}

int rad_acct_cb_r(int tries, const char *config,
		int(*cb)(rad_cb_action, const void *, void *),
		const void *arg, char *errmsg)
{
	struct acct_args a;
	a.cb = cb;
	a.arg = arg;
	return loop_servers(config, tries, try_acct_one_server, (void *)&a, errmsg);
}

/* vim:set noet sw=8 ts=8: */
