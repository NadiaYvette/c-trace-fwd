#include <stddef.h>
#include <stdlib.h>
#include "c_trace_fwd.h"

int
setup_state(struct c_trace_fwd_state **state, struct c_trace_fwd_conf *conf)
{
	int retval = RETVAL_FAILURE;

	*state = calloc(1, sizeof(struct c_trace_fwd_state));
	(*state)->unix_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if ((*state)->unix_sock_fd == -1)
		goto exit_failure;
	if (connect((*state)->unix_sock_fd, (struct sockaddr *)&conf->unix_sock, sizeof(struct sockaddr_un)))
		goto exit_shutdown;
	retval = RETVAL_SUCCESS;
	return retval;
exit_shutdown:
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
	free(*state);
	*state = NULL;
}
