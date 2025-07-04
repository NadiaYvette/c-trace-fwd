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
		struct tof_request *req = &tof->tof_msg_body.request;
		struct tof_msg *reply_msg = NULL;
		int ret;

		ctf_msg(service_unix, "tof_request case to "
				"to_queue_answer_request()\n");
		switch (ret = to_queue_answer_request(state, req, &reply_msg)) {
		case svc_req_must_block:
			ctf_msg(service_unix, "returning "
					"svc_req_must_block\n");
			retval = RETVAL_SUCCESS;
			break;
		case svc_req_none_available:
			ctf_msg(service_unix, "returning "
					"svc_req_none_available\n");
			retval = RETVAL_SUCCESS;
			break;
		case svc_req_failure:
			ctf_msg(service_unix, "returning "
					"svc_req_failure\n");
			retval = RETVAL_FAILURE;
			break;
		case svc_req_success:
			size_t msg_size = 0;
			char *msg_buf;

			if (!(msg_buf = ctf_proto_stk_encode(reply_msg, &msg_size))) {
				/* trace_objects to transfer lost here */
				ctf_msg(service_unix, "svc_req_failure"
						"ctf_proto_stk_encode() "
						"failed\n");
				tof_free(reply_msg);
				retval = RETVAL_FAILURE;
				break;
			}
			if (write(state->unix_sock_fd, msg_buf, msg_size)
						!= (ssize_t)msg_size) {
				/* connection left in bad state, lost
				 * trace_objects, leaked memory
				 * could even be a short write */
				ctf_msg(service_unix, "svc_req_failure"
						"write() failed\n");
				tof_free(reply_msg);
				retval = RETVAL_FAILURE;
				break;
			}
			retval = RETVAL_SUCCESS;
			break;
		default:
			ctf_msg(service_unix, "unrecognized "
					"to_queue_answer_request() "
					"return value %d!\n", ret);
			tof_free(reply_msg);
			retval = RETVAL_FAILURE;
			break;
		}
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
