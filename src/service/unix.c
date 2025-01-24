#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "c_trace_fwd.h"
#include "proto_stk.h"
#include "service.h"
#include "tof.h"

int
service_unix_sock(struct c_trace_fwd_state *state)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf;
	ssize_t ret_sz;
	struct tof_msg *tof;
	struct tof_reply *reply;

	if (!(buf = calloc(1024, 1024)))
		return RETVAL_FAILURE;
retry_read:
	ret_sz = read(state->unix_sock_fd, buf, 1024 * 1024);
	if (ret_sz <= 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			goto exit_free_buf;
		errno = 0;
		goto retry_read;
	}
	if (!(tof = ctf_proto_stk_decode(buf)))
		goto exit_free_buf;
	if (tof->tof_msg_type != tof_reply)
		goto exit_free_buf;
	reply = &tof->tof_msg_body.reply;
	retval = to_enqueue_multi(state, reply->tof_replies, reply->tof_nr_replies);
exit_free_buf:
	free(buf);
	return retval;
}
