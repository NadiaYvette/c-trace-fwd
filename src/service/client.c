#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "proto_stk.h"
#include "sdu.h"
#include "service.h"
#include "tof.h"

struct ctf_proto_stk_decode_result *
service_recv_tof(struct c_trace_fwd_state *state, int fd)
{
	struct ctf_proto_stk_decode_result *cpsdr = NULL;
	char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;

	if (!(buf = calloc(64, 1024)))
		return NULL;
	sz = 64 * 1024;
	cur_buf = buf;
	cur_sz = sz;
retry_read:
	if ((ret_sz = recv(fd, cur_buf, cur_sz, MSG_DONTWAIT)) == cur_sz)
		cpsdr = ctf_proto_stk_decode(buf);
	else if (!ret_sz) {
		if (!errno) /* all ready data consumed */
			cpsdr = ctf_proto_stk_decode(buf);
		else if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry_read;
	} else if (ret_sz > 0) {
		cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
		cur_sz -= MIN(cur_sz, ret_sz);
		(void)!sched_yield();
		goto retry_read;
	}
/* out_free_buf: */
	free(buf);
	return cpsdr;
}

int
service_send_tof(struct c_trace_fwd_state *state, struct tof_msg *tof, int fd)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;

	if (!(buf = ctf_proto_stk_encode(tof, &sz)))
		return RETVAL_FAILURE;
	/* This is an awkward enough pattern that the API should change. */
	cur_buf = buf;
	cur_sz = sz;
retry_send:
	ret_sz = send(fd, cur_buf, cur_sz, MSG_CONFIRM | MSG_NOSIGNAL);
	if (ret_sz == (ssize_t)cur_sz)
		retval = RETVAL_SUCCESS;
	else if (!ret_sz && !errno) { /* EOF */
		retval = RETVAL_SUCCESS;
		goto out_free_buf;
	} else if (!ret_sz && errno != EAGAIN && errno != EWOULDBLOCK)
		goto out_free_buf;
	else if (ret_sz >= 0) {
		cur_buf = &cur_buf[MIN(cur_sz, ret_sz)];
		cur_sz -= MIN(cur_sz, ret_sz);
		(void)!sched_yield();
		goto retry_send;
	}
out_free_buf:
	free(buf);
	return retval;
}

static struct tof_msg *
service_build_reply(struct c_trace_fwd_state *state, struct tof_request *req)
{
	struct tof_msg *msg = NULL;

	if (to_queue_answer_request(state, req, &msg) == svc_req_success)
		return msg;
	return NULL;
}

void
service_client_destroy(struct c_trace_fwd_state *state, int fd)
{
	(void)!shutdown(fd, SHUT_RDWR);
	(void)!close(fd);
	FD_CLR(fd, &state->state_fds);
	state->nr_clients--;
}

int
service_client_sock(struct c_trace_fwd_state *state, struct pollfd *pollfd)
{
	int retval = RETVAL_FAILURE;
	struct ctf_proto_stk_decode_result *cpsdr;
	struct tof_msg *tof;

	if (!!(pollfd->revents & (POLLERR|POLLHUP))) {
		service_client_destroy(state, pollfd->fd);
		return RETVAL_SUCCESS;
	}
	if (!(pollfd->revents & (POLLIN|POLLPRI)))
		return RETVAL_SUCCESS;
	if (!(cpsdr = service_recv_tof(state, pollfd->fd)))
		return RETVAL_FAILURE;
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
	case tof_done:
		break;
	case tof_reply:
		/* Replies themselves don't need answering, but the
		 * contents they're delivering may need handling
		 * e.g. insertion of returned data into queues. */
		break;
	case tof_request:
		struct tof_msg *tof_reply_msg;
		struct tof_request *req = &tof->tof_msg_body.request;

		if (!(tof_reply_msg = service_build_reply(state, req)))
			goto out_free_cpsdr;
		if (service_send_tof(state, tof_reply_msg, pollfd->fd) == RETVAL_SUCCESS)
			retval = RETVAL_SUCCESS;
		tof_free(tof_reply_msg);
		break;
	default:
		ctf_msg(client, "bad tof_msg_type %d\n", tof->tof_msg_type);
		goto out_free_tof;
	}
out_free_cpsdr:
	free(cpsdr);
out_free_tof:
	tof_free(tof);
	return retval;
}
