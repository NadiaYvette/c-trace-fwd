#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "ctf_util.h"
#include "c_trace_fwd.h"
#include "proto_stk.h"
#include "queue.h"
#include "service.h"
#include "tof.h"

static enum svc_result
service_unix_sock_send_done(struct c_trace_fwd_state *state, int fd)
{
	struct tof_msg done_msg = {
		.tof_msg_type = tof_done,
		.tof_msg_body = {
			.request = {
				.tof_blocking = 0,
				.tof_nr_obj   = 0,
			},
		},
	};
	if (service_send_tof(state, &done_msg, fd) != RETVAL_SUCCESS) {
		ctf_msg(unix, "service_send_tof() failed\n");
		return svc_progress_fail;
	}
	/* state->agency = agency_remote; */
	ctf_set_agency(unix, &state->unix_io, agency_remote);
	return svc_progress_send;
}

/* here "nonremote" means local or nobody
 * It's unclear when it would ever be nobody. */
static enum svc_result
service_unix_sock_send(struct c_trace_fwd_state *state, int fd)
{
	struct tof_request request = {
		.tof_blocking = 0,
		.tof_nr_obj   = 64,
	};
	struct tof_msg *msg = NULL;
	enum svc_result retval;
	enum svc_req_result svc_req_ret;

	ctf_msg(unix, "calling to_queue_answer_request()\n");
	switch (svc_req_ret = to_queue_answer_request(&state->unix_io.in_queue, &request, &msg)) {
	case svc_req_success:
		ctf_msg(unix, "svc_req_success\n");
		/* send */
		if (service_send_tof(state, msg, fd) != RETVAL_SUCCESS)
			retval = svc_progress_fail;
		else
			retval = svc_progress_send;
		tof_free(msg);
		/* will this work? */
		if (state->unix_io.agency == agency_nobody) {
			ctf_msg(unix, "sending done\n");
			(void)!service_unix_sock_send_done(state, fd);
		}
		/* change agency to remote */
		/* state->agency = agency_remote; */
		ctf_set_agency(unix, &state->unix_io, agency_remote);
		break;
	case svc_req_must_block:
	case svc_req_none_available:
		ctf_msg(unix, "svc_req_%s\n",
			svc_req_ret == svc_req_must_block ? "must_block"
							: "none_available");
		retval = svc_progress_none;
		if (state->unix_io.agency != agency_nobody)
			break;
		ctf_msg(unix, "sending done\n");
		if (service_unix_sock_send_done(state, fd) == svc_progress_fail)
			retval = svc_progress_fail;
		break;
	case svc_req_failure:
	default:
		if (svc_req_ret == svc_req_failure)
			ctf_msg(unix, "svc_req_failure\n");
		else
			ctf_msg(unix, "svc_req_ret value unknown\n");
		retval = svc_progress_fail;
		break;
	}
	return retval;
}

static enum svc_result
service_unix_sock_recv(struct c_trace_fwd_state *state, int fd)
{
	enum svc_result retval = svc_progress_fail;
	struct ctf_proto_stk_decode_result *cpsdr;
	struct tof_msg *tof;
	struct tof_reply *reply;
	int enq_ret;

	/* receive */
	/* change agency to local */
	if (!(cpsdr = service_recv_tof(state, fd))) {
		ctf_msg(service_unix, "service_recv_tof() failed!\n");
		goto out_msg;
	}
	/* state->agency = agency_local; */
	ctf_set_agency(unix, &state->unix_io, agency_local);
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
		/* Is a reply needed? */
		tof = NULL;
		if (!!cpsdr->proto_stk_decode_result_body.undecoded)
			ctf_cbor_decref(unix, &cpsdr->proto_stk_decode_result_body.undecoded);
		goto out_free_cpsdr;
	}
tof_msg_type_switch:
	switch (tof->tof_msg_type) {
	case tof_reply:
		ctf_msg(service_unix, "tof_reply case about to_enqueue_multi()\n");
		reply = &tof->tof_msg_body.reply;
		enq_ret = to_enqueue_multi(&state->unix_io.in_queue, reply->tof_replies, reply->tof_nr_replies);
		if (enq_ret != RETVAL_SUCCESS)
			ctf_msg(service_unix, "to_enqueue_multi() failed\n");
		state->unix_io.agency = agency_local;
		break;
	case tof_request:
		struct tof_request *req = &tof->tof_msg_body.request;
		struct tof_msg *reply_msg = NULL;
		int ret;

		ctf_msg(service_unix, "tof_request case to "
				"to_queue_answer_request()\n");
		/* state->agency = agency_local; */
		ctf_set_agency(unix, &state->unix_io, agency_local);
		switch (ret = to_queue_answer_request(&state->unix_io.out_queue, req, &reply_msg)) {
		case svc_req_must_block:
			ctf_msg(service_unix, "returning "
					"svc_req_must_block\n");
			retval = svc_progress_none;
			break;
		case svc_req_none_available:
			ctf_msg(service_unix, "returning "
					"svc_req_none_available\n");
			retval = svc_progress_none;
			break;
		case svc_req_failure:
			ctf_msg(service_unix, "returning "
					"svc_req_failure\n");
			retval = svc_progress_fail;
			break;
		case svc_req_success:
			if (service_send_tof(state, reply_msg, fd) != RETVAL_SUCCESS)
				retval = svc_progress_fail;
			else {
				/* state->agency = agency_remote; */
				ctf_set_agency(unix, &state->unix_io, agency_remote);
				retval = svc_progress_send;
			}
			break;
		default:
			ctf_msg(service_unix, "unrecognized "
					"to_queue_answer_request() "
					"return value %d!\n", ret);
			tof_free(reply_msg);
			retval = svc_progress_fail;
			break;
		}
		break;
	case tof_done:
		ctf_msg(service_unix, "tof_done case no-op\n");
		/* state->agency = agency_local; */
		ctf_set_agency(unix, &state->unix_io, agency_local);
		retval = svc_progress_recv;
		break;
	default:
		ctf_msg(service_unix, "unhandled tof_msg_type %d\n",
				      tof->tof_msg_type);
		break;
	}
out_free_cpsdr:
	free(cpsdr);
out_msg:
	ctf_msg(service_unix, "reached out_free_buf label\n");
	if (retval != RETVAL_SUCCESS)
		ctf_msg(service_unix, "service_unix_core() failed!\n");
	return retval;
}

enum svc_result
service_unix_sock(struct c_trace_fwd_state *state, struct pollfd *pollfd)
{
	switch (state->unix_io.agency) {
	case agency_nobody:
		if (!!(pollfd->revents & POLLIN)) {
			ctf_msg(unix, "agency_nobody service_unix_sock_recv()\n");
			return service_unix_sock_recv(state, pollfd->fd);
		}
		if (!!(pollfd->revents & POLLOUT)) {
			ctf_msg(unix, "agency_nobody service_unix_sock_send()\n");
			return service_unix_sock_send(state, pollfd->fd);
		}
		ctf_msg(unix, "agency_nobody no events\n");
		return svc_progress_none;
	case agency_local:
		if (!!(pollfd->revents & POLLOUT)) {
			ctf_msg(unix, "agency_local service_unix_sock_send()\n");
			return service_unix_sock_send(state, pollfd->fd);
		}
		ctf_msg(unix, "agency_local no events\n");
		return svc_progress_none;
	case agency_remote:
		if (!!(pollfd->revents & POLLIN)) {
			ctf_msg(unix, "agency_remote service_unix_sock_recv()\n");
			return service_unix_sock_recv(state, pollfd->fd);
		}
		ctf_msg(unix, "agency_remote no events\n");
		return svc_progress_none;
	default:
		ctf_msg(service, "unrecognized agency %d\n", state->unix_io.agency);
		return svc_progress_fail;
	}
}

int
service_unix_sock2(struct c_trace_fwd_state *state)
{
	unsigned retry_counter = 64;
	int retval = RETVAL_FAILURE, flg = MSG_CONFIRM | MSG_NOSIGNAL;
	unsigned char *buf, *cur_buf;
	ssize_t ret_sz, sz, cur_sz;
	struct ctf_proto_stk_decode_result *cpsdr;
	struct tof_msg *tof;
	struct tof_reply *reply;

	ctf_msg(service_unix, "entered service_unix_sock()\n");
	if (!(buf = calloc(64, 1024))) {
		ctf_msg(service_unix, "calloc() failed!\n");
		return RETVAL_FAILURE;
	}
	ctf_msg(service_unix, "service_unix_sock() about to read()\n");
	sz = 64 * 1024;
	cur_sz = sz;
	cur_buf = buf;
retry_read:
	if ((ret_sz = recv(state->unix_io.fd, cur_buf, cur_sz, 0)) == cur_sz)
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
			ctf_cbor_decref(unix, &cpsdr->proto_stk_decode_result_body.undecoded);
		goto out_free_cpsdr;
	}
tof_msg_type_switch:
	switch (tof->tof_msg_type) {
	case tof_reply:
		ctf_msg(service_unix, "tof_reply case about to_enqueue_multi()\n");
		reply = &tof->tof_msg_body.reply;
		retval = to_enqueue_multi(&state->unix_io.in_queue, reply->tof_replies, reply->tof_nr_replies);
		if (retval != RETVAL_SUCCESS)
			ctf_msg(service_unix, "to_enqueue_multi() failed\n");
		break;
	case tof_request:
		struct tof_request *req = &tof->tof_msg_body.request;
		struct tof_msg *reply_msg = NULL;
		int ret;

		ctf_msg(service_unix, "tof_request case to "
				"to_queue_answer_request()\n");
		switch (ret = to_queue_answer_request(&state->unix_io.in_queue, req, &reply_msg)) {
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
			if (send(state->unix_io.fd, msg_buf, msg_size, flg)
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
