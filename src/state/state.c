#include <cbor.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include "c_trace_fwd.h"

int
setup_state(struct c_trace_fwd_state **state, struct c_trace_fwd_conf *conf)
{
	struct addrinfo *ux_addr;
	struct sockaddr *unix_sock;
	socklen_t ai_addrlen;
	int ai_family, ai_socktype, ai_protocol, unix_sock_fd,
	    page_size, retval = RETVAL_FAILURE;

	*state = calloc(1, sizeof(struct c_trace_fwd_state));
	(*state)->unix_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if ((*state)->unix_sock_fd == -1)
		goto exit_failure;
	page_size = getpagesize();
	if (page_size < 0)
		goto exit_shutdown_unix;
	(*state)->item_tbl = calloc(page_size, sizeof(cbor_item_t *));
	if (!(*state)->item_tbl)
		goto exit_shutdown_unix;
	(*state)->item_tbl_sz = page_size;
	unix_sock_fd = (*state)->unix_sock_fd;
	unix_sock = (struct sockaddr *)&conf->unix_sock;
	if (connect(unix_sock_fd, unix_sock, sizeof(struct sockaddr_un)))
		goto exit_free_items;
	ux_addr = conf->ux_addr;
	ai_family = ux_addr->ai_family;
	ai_socktype = ux_addr->ai_socktype;
	ai_protocol = ux_addr->ai_protocol;
	ai_addrlen = ux_addr->ai_addrlen;
	(*state)->ux_sock_fd = socket(ai_family, ai_socktype, ai_protocol);
	if ((*state)->ux_sock_fd == -1)
		goto exit_shutdown_unix;
	if (bind((*state)->ux_sock_fd, ux_addr->ai_addr, ai_addrlen))
		goto exit_shutdown_ux;
	retval = RETVAL_SUCCESS;
	return retval;
exit_shutdown_ux:
	shutdown((*state)->ux_sock_fd, SHUT_RDWR);
exit_free_items:
	free((*state)->item_tbl);
	(*state)->item_tbl = NULL;
	(*state)->item_tbl_sz = 0;
exit_shutdown_unix:
	shutdown((*state)->unix_sock_fd, SHUT_RDWR);
exit_failure:
	free(*state);
	*state = NULL;
	return retval;
}

void
teardown_state(struct c_trace_fwd_state **state)
{
	shutdown((*state)->unix_sock_fd, SHUT_RDWR);
	shutdown((*state)->ux_sock_fd, SHUT_RDWR);
	free((*state)->item_tbl);
	(*state)->item_tbl = NULL;
	(*state)->item_tbl_sz = 0;
	free(*state);
	*state = NULL;
}
