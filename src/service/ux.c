#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "c_trace_fwd.h"

int
service_ux_sock(struct ctf_state *state)
{
	int new_fd = accept(state->ux_sock_fd, NULL, NULL);
	struct io_queue *new_ux_io;

	if (new_fd < 0)
		return RETVAL_FAILURE;
	if (!state->nr_clients)
		new_ux_io = calloc(1, sizeof(struct io_queue));
	else
		new_ux_io = reallocarray(state->ux_io, state->nr_clients + 1, sizeof(struct io_queue));
	if (!new_ux_io)
		goto out_close;
	state->ux_io = new_ux_io;
	(void)!io_queue_init(&new_ux_io[state->nr_clients], new_fd);
	state->nr_clients++;
	FD_SET(new_fd, &state->state_fds);
	return RETVAL_SUCCESS;
out_close:
	(void)!shutdown(new_fd, SHUT_RDWR);
	(void)!close(new_fd);
	return RETVAL_FAILURE;
}
