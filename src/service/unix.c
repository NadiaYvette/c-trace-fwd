#include <errno.h>
#include <sched.h>
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
	unsigned retry_counter = 64;
	int retval = RETVAL_FAILURE, flg = MSG_CONFIRM | MSG_NOSIGNAL;
	unsigned char *buf, *cur_buf;
	ssize_t ret_sz, sz, cur_sz;
	struct ctf_proto_stk_decode_result *cpsdr;
	struct tof_msg *tof;
	struct tof_reply *reply;

	ctf_msg(service_unix, "entered service_unix_sock()\n");
	if (!(buf = calloc(1024, 1024))) {
		ctf_msg(service_unix, "calloc() failed!\n");
		return RETVAL_FAILURE;
	}
retry_read:
	ctf_msg(service_unix, "service_unix_sock() about to read()\n");
	sz = 1024 * 1024;
	cur_sz = sz;
	cur_buf = buf;
	if ((ret_sz = recv(state->unix_sock_fd, cur_buf, cur_sz, 0)) == cur_sz)
		goto got_past_read;
	if (ret_sz <= 0) {
		if (!!errno && errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK) {
			ctf_msg(service_unix, "fatal read error! "
					"errno = %d (%s)!\n",
					errno, strerror(errno));
			goto out_free_buf;
		}
		errno = 0;
	}
	if (!!sched_yield()) {
		ctf_msg(service_unix, "sched_yield() error! "
				"errno = %d (%s)!\n",
				errno, strerror(errno));
		errno = 0;
		/* There isn't really anything to do. It just
		 * theoretically cedes the CPU to programs that
		 * might need it more. */
	}
	cur_buf = &cur_buf[ret_sz];
	cur_sz -= ret_sz;
	if (!--retry_counter)
		goto out_free_buf;
	goto retry_read;
got_past_read:
	if (!(cpsdr = ctf_proto_stk_decode(buf))) {
		ctf_msg(service_unix, "tof decode failed!\n");
		goto out_free_buf;
	}
	switch (cpsdr->sdu.sdu_proto_un.sdu_proto_num) {
	case mpn_trace_objects:
		tof = cpsdr->proto_stk_decode_result_body.tof_msg;
		/* It could be break, but the label's name is descriptive. */
		goto tof_msg_type_switch;
	default:
		ctf_msg(client, "bad sdu_proto_num %d\n",
				cpsdr->sdu.sdu_proto_un.sdu_proto_num);
		/* Deliberate fall-through; more properly, the other
		 * cases are skipping over the log message from the
		 * default case. */
	case mpn_EKG_metrics:
	case mpn_data_points:
		/* These protocols' CBOR contents aren't decoded. */
		tof = NULL;
		if (!!cpsdr->proto_stk_decode_result_body.undecoded)
			cbor_decref(&cpsdr->proto_stk_decode_result_body.undecoded);
		goto out_free_cpsdr;
	}
tof_msg_type_switch:
	switch (tof->tof_msg_type) {
	case tof_reply:
		ctf_msg(service_unix, "tof_reply case about to_enqueue_multi()\n");
		reply = &tof->tof_msg_body.reply;
		retval = to_enqueue_multi(state, reply->tof_replies, reply->tof_nr_replies);
		if (retval != RETVAL_SUCCESS)
			ctf_msg(service_unix, "to_enqueue_multi() failed\n");
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
			if (send(state->unix_sock_fd, msg_buf, msg_size, flg)
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
out_free_cpsdr:
	free(cpsdr);
out_free_buf:
	ctf_msg(service_unix, "reached out_free_buf label\n");
	free(buf);
	if (!!retval)
		ctf_msg(service_unix, "service_unix_core() failed!\n");
	return retval;
}
