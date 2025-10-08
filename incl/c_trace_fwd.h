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
#include "agency.h"
#include "queue.h"

#define RETVAL_SUCCESS EXIT_SUCCESS
#define RETVAL_FAILURE EXIT_FAILURE
#define CTF_INIT_OR_RESP false

struct cbor_item_t;
struct tof_msg;

struct ctf_conf {
	/* The path length is limited by this structure. */
	struct addrinfo *ux_addr;
	struct sockaddr_un unix_sock;
	char *preload_queue;
	bool threaded_service;
};

struct ctf_state {
	int ux_sock_fd;
	struct io_queue unix_io;
	struct io_queue *ux_io;
	int nr_clients;
	fd_set state_fds;
	pthread_mutex_t state_lock;
};

struct ctf_stk_state {
	ssize_t stack_top; /* negative for empty stack */
	size_t stack_sz;
	struct cbor_item_t **stack; /* to parse nested structures */
};

struct ctf_thread_arg {
	struct ctf_conf *conf;
	struct ctf_state *state;
};

int setup_conf(struct ctf_conf **, int, char *[]);
int setup_state(struct ctf_state **, struct ctf_conf *);
void teardown_state(struct ctf_state **);
void teardown_conf(struct ctf_conf **);
