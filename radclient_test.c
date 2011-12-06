#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <libradius.h>
#include <radpaths.h>
#include <conf.h>

#define strlcpy(A,B,C) strncpy(A,B,C), *(A+(C)-1)='\0'
#define BUFSIZE 1024

struct rad_server;
struct rad_server {
	char name[64];
	char host[64];
	int port;
	char bind[64];
	char secret[64];
	enum { NONE, PAP, CHAP } method;
	struct rad_server *next;
};

static struct rad_server *parse_one_server(char *buf);
static struct rad_server *parse_servers(const char *config);
static int find_statement(char *buf);
int rad_auth(const char *username, const char *password,
		const char *host, const char *config);

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

	if((fp = fopen(config, "r")) == NULL)
		return NULL;

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

		if(!s_len) {
			if(!find_statement(buf))
				continue;
		} else if(s_len + b_len + 1 > s_size) {
			s_size += BUFSIZE;
			stm = realloc(stm, s_size);
			if(!stm)
				return NULL;
		}

		brace = strrchr(buf, '}');
		if(brace && (brace == buf ||
				*(brace-1) == ' ' && *(brace-1) == '\t')) {
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
#ifdef DEBUG
		fprintf(stderr, "adding: %s:%d (%s) %s\n",
			cur->host, cur->port,
			cur->method == CHAP ? "CHAP" : "PAP",
			cur->secret);
#endif
	}

#ifdef DEBUG
	if(s_len > 0)
		fprintf(stderr, "reached EOF, could not find closing '}'!\n");
#endif

	free(stm);
	fclose(fp);

	return head;
}

/* find "foobar {" part */
static int find_statement(char *buf)
{
	const char delim[4] = " \t\n";
	char tmp[BUFSIZE];
	char *t;
	strlcpy(tmp, buf, BUFSIZE);
	t = strtok(tmp, delim);
	if(!t) /* no statement */
		return 0;
	if((t = strtok(NULL, delim)) && *t == '{')
		return 1;
	return 0;
}

static struct rad_server *parse_one_server(char *buf)
{
	struct rad_server *s;
	const char delim[4] = " \t\n";
	char *t, *v;
	char token[64];

	s = malloc(sizeof(*s));
	if(!s) {
		free(s);
		return NULL;
	}

	if(!(t = strtok(buf, delim))) {
		free(s);
		return NULL;
	}
	strlcpy(s->name, t, 64);

	/* fill with defaults */
	*(s->host) = '\0';
	*(s->secret) = '\0';
	s->port = 1812;
	s->method = NONE;
	strcpy(s->bind, "0.0.0.0");

	if(!(t = strtok(NULL, delim)) || *t != '{') {
		free(s);
		return NULL;
	}

	while((t = strtok(NULL, delim)) && *t != '}') {
		strlcpy(token, t, 64);
		v = strtok(NULL, delim);
		if(!strcmp(token, "host"))
			strlcpy(s->host, v, sizeof(s->host));
		else if(!strcmp(token, "bind"))
			strlcpy(s->bind, v, sizeof(s->bind));
		else if(!strcmp(token, "secret"))
			strlcpy(s->secret, v, sizeof(s->secret));
		else if(!strcmp(token, "port"))
			s->port = atoi(v);
		else if(!strcmp(token, "method")) {
			if(!strcasecmp(v, "CHAP"))
				s->method = CHAP;
			else if(!strcasecmp(v, "PAP"))
				s->method = PAP;
			else
				return NULL;
		} else {
#ifdef DEBUG
			fprintf(stderr, "wrong key: %s = %s\n", token, v);
#endif
		}
	}

	if(!*(s->host) || s->method == NONE) {
#ifdef DEBUG
		fprintf(stderr, "%s: error in format: "
			"host or method missing\n", s->name);
#endif
		free(s);
		return NULL;
	}

	s->next = NULL;
	return s;
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

static int ipaddr_from_server(struct in_addr *addr, const char *host)
{
	struct hostent *res;

	if(!(res = gethostbyname(host))) {
#ifdef DEBUG
		fprintf(stderr, "Failed to resolve host '%s'.\n", host);
#endif
		return 0;
	}

	addr->s_addr = ((struct in_addr*) res->h_addr_list[0])->s_addr;
	return 1;
}


int main(int argc, char *argv[])
{
	char username[32], password[32];

	if(argc != 3) {
		fprintf(stdout, "<user> <pw>: ");
		fscanf(stdin, "%31s %31s", &username, &password);
	} else {
		strncpy(username, argv[1], 31);
		strncpy(password, argv[2], 31);
	}

	return rad_auth(username, password, "localhost", "servers");
}

int rad_auth(const char *username, const char *password,
		const char *host, const char *config)
{
	struct timeval tv;
	volatile int max_fd;
	fd_set set;

	fr_ipaddr_t client;
	fr_packet_list_t *pl;
	VALUE_PAIR *vp;
	RADIUS_PACKET *request = 0, *reply = 0;

	struct rad_server *serverlist, *server;

	int rc = -1;

	/* if (dict_init(RADDBDIR, RADIUS_DICTIONARY) < 0) { */
	if (dict_init(".", RADIUS_DICTIONARY) < 0) {
		fr_perror("dict_init");
		rc = -1;
		goto done;
	}

	serverlist = parse_servers(config);
	if(!serverlist) {
		printf("Could not parse servers!\n");
		rc = -1;
		goto done;
	}
	server = serverlist;
	do {
		if(!strcasecmp(server->host, host))
			break;
		server = server->next;
	} while(server);
	if(!server) {
#ifdef DEBUG
		fprintf(stderr, "Error: '%s' not found in config file '%s'.\n",
			host, "servers");
#endif
		rc = -1;
		goto done;
	}
#ifdef DEBUG
	fprintf(stderr, "Using server: %s:%d\n", server->host, server->port);
#endif

	request = rad_alloc(1);
	if(!request) {
		fr_perror("foo");
		rc = -1;
		goto done;
	}

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
	if(!sockfd) {
		fr_perror("fr_socket");
		rc = -1;
		goto done;
	}
	/* request->sockfd = sockfd; */
	request->sockfd = -1;
	request->code = PW_AUTHENTICATION_REQUEST;

	pl = fr_packet_list_create(1);
	if(!pl) {
		fr_perror("fr_packet_list_create");
		rc = -1;
		goto done;
	}

	if(!fr_packet_list_socket_add(pl, sockfd)) {
		fr_perror("fr_packet_list_socket_add");
		rc = -1;
		goto done;
	}

	/* construct value pairs */
	vp = pairmake("User-Name", username, 0);
	pairadd(&request->vps, vp);
	vp = pairmake("CHAP-Password", password, 0);
	pairadd(&request->vps, vp);
	/* request->vps = readvp2(stdin, &done, "readvp2"); */

	if(fr_packet_list_id_alloc(pl, request) < 0) {
		fr_perror("fr_packet_list_id_alloc");
		rc = -1;
		goto done;
	}

	if ((vp = pairfind(request->vps, PW_CHAP_PASSWORD)) != NULL) {
		strlcpy(vp->vp_strvalue, password,
			sizeof(vp->vp_strvalue));
		vp->length = strlen(vp->vp_strvalue);

		rad_chap_encode(request, vp->vp_octets, request->id, vp);
		vp->length = 17;
	}

	if(rad_send(request, NULL, server->secret) == -1) {
		fr_perror("rad_send");
		rc = -1;
		goto done;
	}

	/* GESENDET! :-) */

	/* And wait for reply, timing out as necessary */
	FD_ZERO(&set);

	max_fd = fr_packet_list_fd_set(pl, &set);
	if (max_fd < 0) {
		rc = -1;
		goto done;
	}

	/* wait 1.5 seconds */
	tv.tv_sec = 1;
	tv.tv_usec = 500;

	if (select(max_fd, &set, NULL, NULL, &tv) <= 0) {
		fprintf(stderr, "no packet received!\n");
		rc = -1;
		goto done;
	}

	reply = fr_packet_list_recv(pl, &set);
	if (!reply) {
		fprintf(stderr, "radclient: received bad packet: %s\n",
				fr_strerror());
		rc = -1;	/* bad packet */
		goto done;
	}

	if (rad_verify(reply, request, server->secret) < 0) {
		fr_perror("rad_verify");
		rc = -1;
		goto done;
	}

	fr_packet_list_yank(pl, request);

	if (rad_decode(reply, request, server->secret) != 0) {
		fr_perror("rad_decode");
		rc = -1;
		goto done;
	}

	if(reply->code == PW_AUTHENTICATION_ACK)
		rc = 0;

	if(reply->code == PW_AUTHENTICATION_REJECT)
		rc = 1;

	done:
	if(request)
		rad_free(&request);
	if(reply)
		rad_free(&reply);
	if(pl)
		fr_packet_list_free(pl);

	return rc;
}

/* vim:set noet sw=8 ts=8: */
