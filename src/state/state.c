#include <cbor.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include "c_trace_fwd.h"
#include "handshake.h"

static struct handshake_propose_version_pair handshake_versions[] = {
	[0] = {
		.propose_version_key = 19,
		.propose_version_value = NULL
	}
};

static struct handshake handshake_proposal = {
	.handshake_type = handshake_propose_versions,
	.handshake_message = {
		.propose_versions = {
			.handshake_propose_versions_len = 1,
			.handshake_propose_versions = handshake_versions
		}
	}
};

static int
state_handshake(struct c_trace_fwd_state *state, struct c_trace_fwd_conf *conf)
{
	struct handshake *handshake_reply;
	cbor_item_t *handshake_proposal_cbor, *reply_cbor;
	unsigned char *buf = NULL;
	size_t buf_sz;
	ssize_t reply_len;
	int retval = RETVAL_FAILURE;

	handshake_proposal_cbor = handshake_encode(&handshake_proposal);
	if (!handshake_proposal_cbor)
		return RETVAL_FAILURE;
	if (!cbor_serialize_alloc(handshake_proposal_cbor, &buf, &buf_sz))
		goto out_decref_proposal;
	if (write(state->unix_sock_fd, buf, buf_sz) <= 0 && errno != 0)
		goto out_free_buf;
	if (buf_sz < 1024 * 1024) {
		unsigned char *new_buf;

		if (!(new_buf = realloc(buf, 1024 * 1024)))
			goto out_free_buf;
		buf_sz = 1024 * 1024;
		buf = new_buf;
	}
	while (!(reply_len = read(state->unix_sock_fd, buf, buf_sz))) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			break;
		errno = 0;
	}
	if (reply_len < 0)
		goto out_free_buf;
	if (!(reply_cbor = cbor_load(buf, reply_len, NULL)))
		goto out_free_buf;
	if (!(handshake_reply = handshake_decode(reply_cbor)))
		goto out_decref_reply;
	if (handshake_reply->handshake_type != handshake_accept_version)
		goto out_decref_reply;
	retval = RETVAL_SUCCESS;
out_decref_reply:
	cbor_decref(&reply_cbor);
out_free_buf:
	free(buf);
out_decref_proposal:
	cbor_decref(&handshake_proposal_cbor);
	return retval;
}

/* This may be worth separating the components of for readability's sake. */
int setup_state(struct c_trace_fwd_state **state, struct c_trace_fwd_conf *conf)
{
	pthread_mutexattr_t state_lock_attr;
	struct addrinfo *ux_addr;
	struct sockaddr *unix_sock;
	socklen_t ai_addrlen;
	int ai_family, ai_socktype, ai_protocol, unix_sock_fd, page_size,
		retval = RETVAL_FAILURE;

	*state = calloc(1, sizeof(struct c_trace_fwd_state));
	if (!*state)
		return RETVAL_FAILURE;
	if (pthread_mutexattr_init(&state_lock_attr))
		goto exit_failure;
	(void)!pthread_mutex_init(&(*state)->state_lock, &state_lock_attr);
	(*state)->stack = calloc(1024, sizeof(cbor_item_t *));
	if (!(*state)->stack)
		goto exit_destroy_mutex;
	(*state)->stack_sz = 1024;
	(*state)->stack_top = -1;
	(*state)->unix_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if ((*state)->unix_sock_fd == -1)
		goto exit_free_stack;
	FD_SET((*state)->unix_sock_fd, &(*state)->state_fds);
	page_size = getpagesize();
	if (page_size < 0)
		goto exit_shutdown_unix;
	unix_sock_fd = (*state)->unix_sock_fd;
	unix_sock = (struct sockaddr *)&conf->unix_sock;
	if (connect(unix_sock_fd, unix_sock, sizeof(struct sockaddr_un)))
		goto exit_shutdown_unix;
	ux_addr = conf->ux_addr;
	ai_family = ux_addr->ai_family;
	ai_socktype = ux_addr->ai_socktype;
	ai_protocol = ux_addr->ai_protocol;
	ai_addrlen = ux_addr->ai_addrlen;
	(*state)->ux_sock_fd = socket(ai_family, ai_socktype, ai_protocol);
	if ((*state)->ux_sock_fd == -1)
		goto exit_shutdown_unix;
	FD_SET((*state)->ux_sock_fd, &(*state)->state_fds);
	if (bind((*state)->ux_sock_fd, ux_addr->ai_addr, ai_addrlen))
		goto exit_shutdown_ux;
	retval = state_handshake(*state, conf);
	return retval;
exit_shutdown_ux:
	(void)!shutdown((*state)->ux_sock_fd, SHUT_RDWR);
	(void)!close((*state)->ux_sock_fd);
	(*state)->ux_sock_fd = 0;
exit_shutdown_unix:
	(void)!shutdown((*state)->unix_sock_fd, SHUT_RDWR);
	(void)!close((*state)->unix_sock_fd);
	(*state)->unix_sock_fd = 0;
exit_free_stack:
	free((*state)->stack);
	(*state)->stack_top = -1;
exit_destroy_mutex:
	(void)!pthread_mutex_destroy(&(*state)->state_lock);
	(void)!pthread_mutexattr_destroy(&state_lock_attr);
exit_failure:
	free(*state);
	*state = NULL;
	return retval;
}

void teardown_state(struct c_trace_fwd_state **state)
{
	(void)!shutdown((*state)->unix_sock_fd, SHUT_RDWR);
	(void)!close((*state)->unix_sock_fd);
	(*state)->unix_sock_fd = 0;
	(void)!shutdown((*state)->ux_sock_fd, SHUT_RDWR);
	(void)!close((*state)->ux_sock_fd);
	(*state)->ux_sock_fd = 0;
	(void)!pthread_mutex_destroy(&(*state)->state_lock);
	free(*state);
	*state = NULL;
}
