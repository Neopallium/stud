/***************************************************************************
 * Copyright (C) 2011 by Robert G. Jakabosky <bobby@sharedrealm.com>       *
 *                                                                         *
 ***************************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <ev.h>

#define SERVER_DEFAULT_HOST "0.0.0.0"
#define SERVER_DEFAULT_PORT "9999"
#define SERVER_DEFAULT_BACKLOG 1024
#define SERVER_DEFAULT_ACCEPT_TIMEOUT 4
#define SERVER_DEFAULT_STATS_INTERVAL 4

#define CLIENT_BUFFER_SIZE 1024
#define CLIENT_MAX_READS 10
#define CLIENT_MIN_READ_BUF 128

typedef struct TestClient TestClient;
typedef struct TestServer TestServer;

/*
 * Test Client.
 */
struct TestClient {
	int fd;
	uint32_t buf_off;
	uint32_t buf_len;
	ev_io io;
	LIST_ENTRY(TestClient) clients;
	char buf[CLIENT_BUFFER_SIZE];
};

/*
 * Test Server
 */
struct TestServer {
	/* options. */
	struct addrinfo *addr;
	const char *host;
	const char *port;
	int backlog;
	int accept_timeout;
	int stats_ts;
	/* loop. */
	struct ev_loop *loop;
	/* server socket. */
	int fd;
	ev_io listener;
	/* signal handlers */
	ev_signal sig_int;
	ev_signal sig_term;
	/* stats timer */
	ev_timer stats;
	/* stats. */
	int num_clients;
	int peak_clients;
	/* clients. */
	LIST_HEAD(listclient, TestClient) clients;
};

/*
 *
 * Common code.
 *
 */
#define return_on_error(func, rc, msg, ret) \
	if(rc < 0) { \
		perror(#func ": " msg); \
		return ret; \
	}

int set_nonblock(int sock, int nonblock) {
	int flags;
	flags = fcntl(sock, F_GETFL);
	return_on_error(set_nonblock, flags, "get flags", flags);
	if(nonblock) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~(O_NONBLOCK);
	}
	flags = fcntl(sock, F_SETFL, flags);
	return_on_error(set_nonblock, flags, "set flags", flags);
	return flags;
}

/*
 * Test Client.
 */
static void testclient_event_cb(struct ev_loop *loop, ev_io *w, int revents);

static TestClient *testclient_new(int fd, struct ev_loop *loop) {
	TestClient *client;
	int val, rc;

	client = (TestClient *)malloc(sizeof(TestClient));
	client->fd = fd;
	client->buf_off = 0;
	client->buf_len = 0;

	/* setup client socket. */
	val = 1;
	rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(int));
	if(rc < 0) {
		perror("testclient_new(): TCP_NODELAY");
		goto error_cleanup;
	}
	if(set_nonblock(fd, 1) < 0) goto error_cleanup;

	/* register socket for read. */
	ev_io_init(&client->io, testclient_event_cb, fd, EV_READ);
	ev_io_start(loop, &(client->io));
	client->io.data = client;

	return client;

error_cleanup:
	close(fd);
	free(client);
	return NULL;
}

static void testclient_free(TestClient *client, struct ev_loop *loop) {
	TestServer *server = (TestServer *)ev_userdata(loop);
	server->num_clients--;

	/* remove from client list. */
	LIST_REMOVE(client, clients);

	if(client->fd >= 0) {
		ev_io_stop(loop, &(client->io));
		close(client->fd);
	}
	free(client);
}

static int testclient_error(TestClient *client, struct ev_loop *loop, const char *msg) {
	switch(errno) {
#if (defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN))
	case EWOULDBLOCK:
#endif
	case EAGAIN:
		/* ignore these errors. */
		break;
	default:
		fprintf(stderr, "testclient_error: %s: %s\n", msg, strerror(errno));
		testclient_free(client, loop);
		return -1;
	}
	return 0;
}

static void testclient_change_events(TestClient *client, struct ev_loop *loop, int write_blocked) {
	ev_io *w = &(client->io);
	int events = 0;

	/* enable reads if we have enought space. */
	if((CLIENT_BUFFER_SIZE - client->buf_len) >= CLIENT_MIN_READ_BUF) {
		events |= EV_READ;
	}
	/* check if writes are blocked. */
	if(write_blocked) {
		events |= EV_WRITE;
	}

	if(w->events == events) {
		/* no changed needed. */
		return;
	}
	ev_io_stop(loop, w);
	ev_io_init(w, testclient_event_cb, client->fd, events);
	ev_io_start(loop, w);
}

static int testclient_write(TestClient *client, struct ev_loop *loop) {
	int rc;
	(void)loop;

	assert(client->buf_len <= CLIENT_BUFFER_SIZE);
	assert(client->buf_off <= client->buf_len);
	do {
		rc = send(client->fd, client->buf + client->buf_off, client->buf_len - client->buf_off, 0);
	} while(rc < 0 && errno == EINTR);
	if(rc > 0) {
		client->buf_off += rc;
		if(client->buf_off == client->buf_len) {
			/* buffer is empty. */
			client->buf_off = 0;
			client->buf_len = 0;
			/* disable writes, make sure reads are enabled. */
			testclient_change_events(client, loop, 0);
		} else {
			/* compact data in buffer. */
			rc = client->buf_off;
			memmove(client->buf, client->buf + rc, client->buf_len - rc);
			client->buf_len -= rc;
			client->buf_off = 0;
			/* still have data to write. */
			testclient_change_events(client, loop, 1);
		}
	} else if(rc < 0) {
		/* check if writing is blocked. */
		if(errno == EAGAIN) {
			testclient_change_events(client, loop, 1);
			return 0;
		}
		return testclient_error(client, loop, "send");
	}

	return 0;
}

static int testclient_read(TestClient *client, struct ev_loop *loop) {
	int rc;
	int i;
	int read_more;

	assert(client->buf_len <= CLIENT_BUFFER_SIZE);
	for(i = 0; i < CLIENT_MAX_READS; i++) {
		do {
			rc = recv(client->fd, client->buf + client->buf_len, CLIENT_BUFFER_SIZE - client->buf_len, 0);
		} while(rc < 0 && errno == EINTR);
		if(rc > 0) {
			/* got data. */
			client->buf_len += rc;
			/* try to read more if the last read filled the buffer. */
			read_more = (CLIENT_BUFFER_SIZE == client->buf_len) ? 1 : 0;
			/* try sending data now. */
			rc = testclient_write(client, loop);
			/* if write error or buffer is not empty, then return. */
			if(rc < 0 || client->buf_len > 0 || read_more == 0) return rc;
			/* empty buffer try reading more data. */
		} else {
			break;
		}
	}
	if(rc == 0) {
		/* connection closed. */
		testclient_free(client, loop);
		return 0;
	}

	return testclient_error(client, loop, "recv");
}

static void testclient_event_cb(struct ev_loop *loop, ev_io *w, int revents) {
	TestClient *client = (TestClient *)w->data;

	if(revents & EV_WRITE) {
		testclient_write(client, loop);
	}
	if(revents & EV_READ) {
		testclient_read(client, loop);
	}
}

/*
 * Test Server.
 */
static TestServer *testserver_new() {
	TestServer *server;
	server = (TestServer *)calloc(1,sizeof(TestServer));
	server->fd = -1;
	return server;
}

static void testserver_free(TestServer *server) {
	TestClient *client, *next;
	struct ev_loop *loop = server->loop;

	/* cleanup server. */
	if(server->addr) freeaddrinfo(server->addr);

	/* close clients. */
	LIST_FOREACH_SAFE(client, &(server->clients), clients, next) {
		testclient_free(client, loop);
	}

	if(server->fd >= 0) {
		ev_io_stop(loop, &(server->listener));
		close(server->fd);
	}

	if(server->loop) {
		ev_loop_destroy(server->loop);
	}
	free(server);
}

static void testserver_accept(struct ev_loop *loop, ev_io *w, int revents) {
	TestServer *server = (TestServer *)w->data;
	TestClient *client;
	int fd;
	(void)loop;
	(void)revents;

	fd = accept(server->fd, NULL, NULL);
	if(fd < 0) {
		switch(errno) {
		case EINTR:
#if (defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN))
		case EWOULDBLOCK:
#endif
		case EAGAIN:
			return;
		default:
			perror("accept");
		}
		return;
	}

	/* create client. */
	client = testclient_new(fd, loop);
	if(client) {
		server->num_clients++;
		if(server->num_clients > server->peak_clients) {
			server->peak_clients = server->num_clients;
		}
		/* add client to list of clients. */
		LIST_INSERT_HEAD(&(server->clients), client, clients);
	}

}

static void testserver_stats_cb(struct ev_loop *loop, ev_timer *w, int revents) {
	TestServer *server = (TestServer *)w->data;
	(void)loop;
	(void)revents;

	fprintf(stdout, "stats: clients: %-6d, peak: %-6d\n", server->num_clients, server->peak_clients);
}

static void testserver_exit_cb(struct ev_loop *loop, ev_signal *w, int revents) {
	(void)revents;

	ev_signal_stop(loop, w);
	ev_break(loop, EVBREAK_ALL);
}

static void print_usage(int argc, char *argv[]);

static int testserver_init(TestServer *server, int argc, char *argv[]) {
	struct addrinfo *addr, hints;
	int rc;
	int c;
	int fd;

	server->host = SERVER_DEFAULT_HOST;
	server->port = SERVER_DEFAULT_PORT;
	server->backlog = SERVER_DEFAULT_BACKLOG;
	server->accept_timeout = SERVER_DEFAULT_ACCEPT_TIMEOUT;
	server->stats_ts = SERVER_DEFAULT_STATS_INTERVAL;

	/* parse command line options. */
	while(1) {
		c = getopt(argc, argv, "h:p:B:A:S:");
		if(c < 0) break;
		switch(c) {
		case 'h':
			server->host = optarg;
			break;
		case 'p':
			server->port = optarg;
			break;
		case 'B':
			server->backlog = atoi(optarg);
			break;
		case 'A':
			server->accept_timeout = atoi(optarg);
			break;
		case 'S':
			server->stats_ts = atoi(optarg);
			break;
		default:
			print_usage(argc, argv);
			return -1;
		}
	}

	/* intialize server. */
	server->loop = ev_default_loop(EVFLAG_AUTO);
	ev_set_userdata(server->loop, server);

	/* parse host/post */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	rc = getaddrinfo(server->host, server->port, &hints, &addr);
	if(rc != 0) {
		fprintf(stderr, "Bad host/port: %s\n", gai_strerror(rc));
		return -1;
	}
	server->addr = addr;

	/* create server socket. */
	fd = socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP);
	return_on_error(testserver_init, fd, "socket", -1);
	server->fd = fd;
	/* register server socket for accepting. */
	ev_io_init(&server->listener, testserver_accept, fd, EV_READ);
	ev_io_start(server->loop, &server->listener);
	server->listener.data = server;
 
	/* register signal handlers. */
	ev_signal_init(&server->sig_int, testserver_exit_cb, SIGINT);
	ev_signal_start(server->loop, &server->sig_int);
	server->sig_int.data = server;
	ev_unref(server->loop);
	ev_signal_init(&server->sig_term, testserver_exit_cb, SIGTERM);
	ev_signal_start(server->loop, &server->sig_term);
	server->sig_term.data = server;
	ev_unref(server->loop);

	/* register stats timer. */
	if(server->stats_ts > 0) {
		ev_timer_init(&server->stats, testserver_stats_cb, server->stats_ts, server->stats_ts);
		ev_timer_start(server->loop, &server->stats);
		server->stats.data = server;
		ev_unref(server->loop);
	}

	c = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(int));
	return_on_error(testserver_init, rc, "SO_REUSEADDR", -1);
#ifdef SO_REUSEPORT
	c = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &c, sizeof(int));
	return_on_error(testserver_init, rc, "SO_REUSEPORT", -1);
#endif
	if(set_nonblock(fd, 1) < 0) return -1;

	/* bind server socket to port. */
	rc = bind(fd, addr->ai_addr, addr->ai_addrlen);
	return_on_error(testserver_init, rc, "bind", -1);

#if TCP_DEFER_ACCEPT
	c = server->accept_timeout;
	rc = setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &c, sizeof(int));
	return_on_error(testserver_init, rc, "TCP_DEFER_ACCEPT", -1);
#endif

	/* put server socket in listen mode and set backlog. */
	rc = listen(fd, server->backlog);
	return_on_error(testserver_init, rc, "listen", -1);

	return 0;
}

static void testserver_start(TestServer *server) {
	ev_loop(server->loop, 0);
}

static void print_usage(int argc, char *argv[]) {
	(void)argc;
	fprintf(stderr, "usage: %s [OPTIONS]\n", argv[0]);

	fprintf(stderr,
"TODO: options.\n"
);
	exit(1);
}

int main(int argc, char *argv[]) {
	TestServer *server;

	server = testserver_new();
	if(testserver_init(server, argc, argv) >= 0) {
		testserver_start(server);
	}
	testserver_free(server);

	return 0;
}

