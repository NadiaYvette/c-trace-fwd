#pragma once

/* for EXIT_SUCCESS and EXIT_FAILURE */
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define RETVAL_SUCCESS EXIT_SUCCESS
#define RETVAL_FAILURE EXIT_FAILURE

struct cbor_item_t;
struct tof_msg;

enum agency {
	agency_local  = 0,
	agency_remote = 1,
	agency_nobody = 2,
};

struct c_trace_fwd_conf {
	/* The path length is limited by this structure. */
	struct addrinfo *ux_addr;
	struct sockaddr_un unix_sock;
	char *preload_queue;
};
struct c_trace_fwd_state {
	int ux_sock_fd;
	enum agency agency;
	int unix_sock_fd;
	int nr_clients;
	fd_set state_fds;
	int nr_to;
	struct trace_object **to_queue;
	ssize_t stack_top; /* negative for empty stack */
	size_t stack_sz;
	struct cbor_item_t **stack; /* to parse nested structures */
	pthread_mutex_t state_lock;
};

int setup_conf(struct c_trace_fwd_conf **, int, char *[]);
int setup_state(struct c_trace_fwd_state **, struct c_trace_fwd_conf *);
void teardown_state(struct c_trace_fwd_state **);
void teardown_conf(struct c_trace_fwd_conf **);
