#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <libradius.h>
#include <radpaths.h>
#include <conf.h>

#define strlcpy(A,B,C) strncpy(A,B,C), *(A+(C)-1)='\0'

struct rad_server;
struct rad_server {
	char host[64];
	int port;
	char bind[64];
	char secret[64];
	enum { PAP, CHAP } method;
	struct rad_server *next;
};

static struct rad_server *parse_one_server(char *buf);
static struct rad_server *parse_servers(const char *config);
int rad_auth(const char *username, const char *password,
		const char *host, const char *config);

static struct rad_server *parse_servers(const char *config)
{
	FILE *fp;
	int n = 0;
	char buf[512];
	struct rad_server *tmp, *cur, *head;

	head = NULL;

	if((fp = fopen(config, "r")) == NULL)
		return NULL;
	while(fgets(buf, 511, fp) != NULL) {
		n++;
		/* skip comments and empty lines */
		if(buf[0] == '\n' || buf[0] == '#')
			continue;
		tmp = parse_one_server(buf);
		if(!tmp) {
#ifdef DEBUG
			fprintf(stderr, "Error in %s, line %d. Skipping!\n",
				config, n);
#endif
			continue;
		}
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

	fclose(fp);

	return head;
}

static struct rad_server *parse_one_server(char *buf)
{
	struct rad_server *s;
	const char delim[4] = " \t\n";
	char *t;

	s = malloc(sizeof(*s));
	if(!s)
		return NULL;

	/* Format: "host port bind secret {pap,chap}\n" */
	if(!(t = strtok(buf, delim)))
		return NULL;
	strlcpy(s->host, t, 64);

	if(!(t = strtok(NULL, delim)))
		return NULL;
	s->port = atoi(t);

	if(!(t = strtok(NULL, delim)))
		return NULL;
	strlcpy(s->bind, t, 64);

	if(!(t = strtok(NULL, delim)))
		return NULL;
	strlcpy(s->secret, t, 64);

	if(!(t = strtok(NULL, delim)))
		return NULL;
	if(!strncasecmp(t, "CHAP", 4))
		s->method = CHAP;
	else if(!strncasecmp(t, "PAP", 3))
		s->method = PAP;
	else
		return NULL;

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
	fr_packet_list_t *pl = 0;
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
