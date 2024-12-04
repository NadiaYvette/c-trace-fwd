#pragma once

/* for EXIT_SUCCESS and EXIT_FAILURE */
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#define RETVAL_SUCCESS EXIT_SUCCESS
#define RETVAL_FAILURE EXIT_FAILURE

struct c_trace_fwd_conf {
	/* The path length is limited by this structure. */
	struct sockaddr_un unix_sock;
};
struct c_trace_fwd_state {
	int unix_sock_fd;
};

int setup_conf(struct c_trace_fwd_conf **, int, char *[]);
int setup_state(struct c_trace_fwd_state **, struct c_trace_fwd_conf *);
int service_loop(struct c_trace_fwd_state *, struct c_trace_fwd_conf *);
void teardown_state(struct c_trace_fwd_state **);
void teardown_conf(struct c_trace_fwd_conf **);
