#include <sys/select.h>
#include <sys/socket.h>
#include "c_trace_fwd.h"

int
service_ux_sock(struct c_trace_fwd_state *state)
{
	int new_fd = accept(state->ux_sock_fd, NULL, NULL);

	if (new_fd < 0)
		return RETVAL_FAILURE;
	state->nr_clients++;
	FD_SET(new_fd, &state->state_fds);
	return RETVAL_SUCCESS;
}
