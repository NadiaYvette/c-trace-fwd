#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "ctf_util.h"
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

	ctf_msg(service_unix, "entered service_unix_sock()\n");
	if (!(buf = calloc(1024, 1024))) {
		ctf_msg(service_unix, "calloc() failed!\n");
		return RETVAL_FAILURE;
	}
retry_read:
	ret_sz = read(state->unix_sock_fd, buf, 1024 * 1024);
	if (ret_sz <= 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			ctf_msg(service_unix, "fatal read error!\n");
			goto exit_free_buf;
		}
		errno = 0;
		goto retry_read;
	}
	if (!(tof = ctf_proto_stk_decode(buf))) {
		ctf_msg(service_unix, "tof decode failed!\n");
		goto exit_free_buf;
	}
	switch (tof->tof_msg_type) {
	case tof_reply:
		ctf_msg(service_unix, "tof_reply case about to_enqueue_multi()\n");
		reply = &tof->tof_msg_body.reply;
		retval = to_enqueue_multi(state, reply->tof_replies, reply->tof_nr_replies);
		break;
	case tof_request:
		ctf_msg(service_unix, "tof_request case unhandled, nopping\n");
		retval = RETVAL_SUCCESS;
		break;
	case tof_done:
		ctf_msg(service_unix, "tof_done case no-op\n");
		retval = RETVAL_SUCCESS;
		break;
	default:
		ctf_msg(service_unix, "unhandled tof_msg_type %d\n",
				      tof->tof_msg_type);
		break;
	}
	if (retval != RETVAL_SUCCESS)
		ctf_msg(service_unix, "to_enqueue_multi() failed\n");
exit_free_buf:
	free(buf);
	if (!!retval)
		ctf_msg(service_unix, "service_unix_core() failed!\n");
	return retval;
}
