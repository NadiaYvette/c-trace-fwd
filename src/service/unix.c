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
service_unix_sock_send_done(struct ctf_state *state, int fd)
{
	struct tof_msg done_msg = {
		.tof_msg_type = tof_done,
		.tof_msg_body = {
			.request = {
				.tof_blocking = true,
				.tof_nr_obj   = 0,
			},
		},
	};
	enum mini_protocol_num mpn = (enum mini_protocol_num)(-1);

	if (service_send_tof(state, &done_msg, fd) != RETVAL_SUCCESS) {
		ctf_msg(unix, "service_send_tof() failed\n");
		return svc_progress_fail;
	}
	/* state->agency = agency_remote; */
	ctf_set_agency(unix, &state->unix_io, relative_agency_they_have, mpn);
	return svc_progress_send;
}

enum svc_result
service_unix_sock_send_empty_reply(struct ctf_state *state, int fd)
{
	struct tof_msg reply_msg = {
		.tof_msg_type = tof_reply,
		.tof_msg_body = {
			.reply = {
				.tof_nr_replies	= 0,
				.tof_replies	= NULL,
			},
		},
	};
	enum mini_protocol_num mpn = (enum mini_protocol_num)(-1);

	if (service_send_tof(state, &reply_msg, fd) != RETVAL_SUCCESS) {
		ctf_msg(unix, "service_send_tof() failed\n");
		return svc_progress_fail;
	}
	/* state->agency = agency_remote; */
	ctf_set_agency(unix, &state->unix_io, relative_agency_they_have, mpn);
	state->unix_io.reply_pending = false;
	return svc_progress_send;
}

/* here "nonremote" means local or nobody
 * It's unclear when it would ever be nobody. */
static enum svc_result
service_unix_sock_send(struct ctf_state *state, int fd)
{
	struct tof_request request = {
		.tof_blocking = true,
		.tof_nr_obj   = 64,
	};
	struct tof_msg *msg = NULL;
	enum svc_result retval;
	enum svc_req_result svc_req_ret;
	enum mini_protocol_num mpn = (enum mini_protocol_num)(-1);

	ctf_msg(unix, "calling to_queue_answer_request()\n");
	switch (svc_req_ret = to_queue_answer_request(&state->unix_io.in_queue, &request, &msg)) {
	case svc_req_success:
		ctf_msg(unix, "svc_req_success\n");
		/* send */
		if (service_send_tof(state, msg, fd) != RETVAL_SUCCESS)
			retval = svc_progress_fail;
		else
			retval = svc_progress_send;
		state->unix_io.reply_pending = false;
		tof_free(msg);
		/* will this work? */
		if (io_queue_agency_get(&state->unix_io, mpn_trace_objects) == relative_agency_we_have) {
			ctf_msg(unix, "sending done\n");
			(void)!service_unix_sock_send_done(state, fd);
		}
		/* change agency to remote */
		/* state->agency = agency_remote; */
		ctf_set_agency(unix, &state->unix_io, relative_agency_they_have, mpn);
		break;
	case svc_req_must_block:
	case svc_req_none_available:
		ctf_msg(unix, "svc_req_%s\n",
			svc_req_ret == svc_req_must_block ? "must_block"
							: "none_available");
		retval = svc_progress_none;
		if (io_queue_agency_get(&state->unix_io, mpn) != relative_agency_we_have)
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
service_unix_sock_recv(struct ctf_state *state, int fd)
{
	enum svc_result retval = svc_progress_fail;
	struct ctf_proto_stk_decode_result *cpsdr;
	struct tof_msg *tof;
	struct tof_reply *reply;
	size_t ret_sz;
	char *ret_buf;
	enum mini_protocol_num mpn;

	ctf_msg(unix, "enter\n");
	/* receive */
	/* change agency to local */
	ctf_msg(unix, "about to service_recv_tof()\n");
	if (!(cpsdr = service_recv_tof(state, fd))) {
		ctf_msg(service_unix, "service_recv_tof() failed!\n");
		goto out_msg;
	}
	ctf_msg(unix, "back from service_recv_tof()\n");
	/* state->agency = agency_local; */
	mpn = cpsdr->sdu.sdu_proto_un.sdu_proto_num;
	ctf_set_agency(unix, &state->unix_io, relative_agency_we_have, mpn);
	ctf_msg(unix, "about to check miniprotocol nr\n");
	switch (mpn) {
	case mpn_trace_objects:
		tof = (struct tof_msg *)cpsdr->proto_stk_decode_result_body;
		/* It could be break, but the label's name is descriptive. */
		goto tof_msg_type_switch;
	case mpn_EKG_metrics:
		ctf_msg(unix, "got metrics msg sending empty reply\n");
		if (!(ret_buf = ctf_proto_stk_encode(mpn_EKG_metrics, NULL, &ret_sz)))
			goto out_free_cpsdr;
		write(fd, ret_buf, ret_sz);
		retval = svc_progress_recv;
		goto out_free_cpsdr;
	case mpn_data_points:
		ctf_msg(unix, "got datapoint msg sending empty reply\n");
		if (!(ret_buf = ctf_proto_stk_encode(mpn_EKG_metrics, NULL, &ret_sz)))
			goto out_free_cpsdr;
		write(fd, ret_buf, ret_sz);
		retval = svc_progress_recv;
		goto out_free_cpsdr;
	default:
		ctf_msg(client, "bad sdu_proto_num %d\n",
				cpsdr->sdu.sdu_proto_un.sdu_proto_num);
		/* Deliberate fall-through; more properly, the other
		 * cases are skipping over the log message from the
		 * default case. */
		/* These protocols' CBOR contents aren't decoded. */
		/* Is a reply needed? */
		tof = NULL;
		if (!!cpsdr->proto_stk_decode_result_body->undecoded)
			ctf_cbor_decref(unix, &cpsdr->proto_stk_decode_result_body->undecoded);
		goto out_free_cpsdr;
	}
	ctf_msg(unix, "finished miniprotocol nr check\n");
tof_msg_type_switch:
	ctf_msg(unix, "about to check ->tof_msg_type\n");
	switch (tof->tof_msg_type) {
	case tof_reply:
		size_t nr_replies;

		ctf_msg(service_unix, "tof_reply case about to_enqueue_multi()\n");
		reply = &tof->tof_msg_body.reply;
		nr_replies = reply->tof_nr_replies;
		if (!to_queue_fillarray(&reply->tof_replies, &state->unix_io.in_queue, &nr_replies))
			ctf_msg(service_unix, "to_queue_fillarray() failed\n");
		ctf_set_agency(state, &state->unix_io,
				relative_agency_we_have, mpn_trace_objects);
		break;
	case tof_request:
		ctf_msg(service_unix, "tof_request case to "
				"to_queue_answer_request()\n");
		ctf_set_agency(unix, &state->unix_io,
				relative_agency_we_have, mpn);
		state->unix_io.reply_pending = true;
		break;
	case tof_done:
		ctf_msg(service_unix, "tof_done case no-op\n");
		ctf_set_agency(unix, &state->unix_io,
				relative_agency_we_have, mpn);
		retval = svc_progress_recv;
		break;
	default:
		ctf_msg(service_unix, "unhandled tof_msg_type %d\n",
				      tof->tof_msg_type);
		break;
	}
	ctf_msg(unix, "finished ->tof_msg_type check\n");
out_free_cpsdr:
	ctf_msg(unix, "at label out_free_cpsdr\n");
	cpsdr_free(cpsdr);
out_msg:
	ctf_msg(service_unix, "at out_msg label\n");
	if (retval == svc_progress_fail)
		ctf_msg(service_unix, "service_unix_sock_recv() failed!\n");
	ctf_msg(unix, "service_unix_sock_recv(): return\n");
	return retval;
}

enum svc_result
service_unix_sock(struct ctf_state *state, struct pollfd *pollfd)
{
	enum mini_protocol_num mpn = (enum mini_protocol_num)(-1);

	ctf_msg(unix, "service_unix_sock() enter\n");
	ctf_msg(unix, "pollfd->revents = 0x%x\n", pollfd->revents);
	render_fd_flags(unix, pollfd->fd);
	switch (io_queue_agency_get(&state->unix_io, mpn)) {
	case agency_nobody:
		if (!!(pollfd->revents & POLLIN)) {
			ctf_msg(unix, "agency_nobody "
					"service_unix_sock_recv()\n");
			return service_unix_sock_recv(state, pollfd->fd);
		}
		if (!!(pollfd->revents & POLLOUT)) {
			ctf_msg(unix, "agency_nobody "
					"service_unix_sock_send()\n");
			return service_unix_sock_send_done(state, pollfd->fd);
		}
		if (!(pollfd->revents & (POLLIN|POLLOUT)))
			ctf_msg(unix, "svc neither POLLIN|POLLOUT agency %s\n", relative_agency_string(io_queue_agency_get(&state->unix_io, mpn)));
		ctf_msg(unix, "agency_nobody no events\n");
		return svc_progress_none;
	case agency_local:
		if (!!(pollfd->revents & POLLOUT)) {
			ctf_msg(unix, "agency_local "
					"service_unix_sock_send()\n");
			if (!state->unix_io.reply_pending)
				return service_unix_sock_send_empty_reply(state, pollfd->fd);
			else
				return service_unix_sock_send(state, pollfd->fd);
		}
		ctf_msg(unix, "agency_local no events\n");
		return svc_progress_none;
	case agency_remote:
		if (!!(pollfd->revents & POLLIN)) {
			ctf_msg(unix, "agency_remote "
					"service_unix_sock_recv()\n");
			return service_unix_sock_recv(state, pollfd->fd);
		}
		ctf_msg(unix, "agency_remote no events\n");
		return svc_progress_none;
	default:
		ctf_msg(service, "unrecognized agency %d\n",
				io_queue_agency_get(&state->unix_io, mpn));
		return svc_progress_fail;
	}
}

int
service_unix_sock2(struct ctf_state *state)
{
	int retval = RETVAL_FAILURE, flg = MSG_CONFIRM | MSG_NOSIGNAL;
	struct ctf_proto_stk_decode_result *cpsdr;
	struct tof_msg *tof;
	struct tof_reply *reply;

	ctf_msg(service_unix, "entered service_unix_sock()\n");
	if (!(cpsdr = ctf_proto_stk_decode(state->unix_io.fd))) {
		ctf_msg(service_unix, "tof decode failed!\n");
		goto out_free_cpsdr;
	}
	switch (cpsdr->sdu.sdu_proto_un.sdu_proto_num) {
	case mpn_trace_objects:
		tof = (struct tof_msg *)cpsdr->proto_stk_decode_result_body;
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
		if (!!cpsdr->proto_stk_decode_result_body->undecoded)
			ctf_cbor_decref(unix, &cpsdr->proto_stk_decode_result_body->undecoded);
		goto out_free_cpsdr;
	}
tof_msg_type_switch:
	switch (tof->tof_msg_type) {
	case tof_reply:
		size_t nr_replies;

		reply = &tof->tof_msg_body.reply;
		nr_replies = reply->tof_nr_replies;
		ctf_msg(service_unix, "tof_reply case about to_enqueue_multi()\n");
		if (!to_queue_fillarray(&reply->tof_replies, &state->unix_io.in_queue, &nr_replies))
			ctf_msg(service_unix, "to_queue_fillarray() failed\n");
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

			if (!(msg_buf = ctf_proto_stk_encode(mpn_trace_objects, (union msg *)reply_msg, &msg_size))) {
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
	cpsdr_free(cpsdr);
	ctf_msg(service_unix, "reached out_free_cpsdr label\n");
	if (!!retval)
		ctf_msg(service_unix, "service_unix_core() failed!\n");
	return retval;
}
