#include <errno.h>
#include <linux/errno.h>
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
#include "queue.h"
#include "sdu.h"
#include "service.h"
#include "tof.h"

struct ctf_proto_stk_decode_result *
service_recv_tof(struct ctf_state *state, int fd)
{
	struct ctf_proto_stk_decode_result *cpsdr = NULL;

	ctf_msg(ctf_debug, client, "enter\n");
	ctf_msg(ctf_debug, client, "about to ctf_proto_stk_decode()\n");
	if (!(cpsdr = ctf_proto_stk_decode(fd))) {
		ctf_msg(ctf_alert, client,
				"ctf_proto_stk_decode() failed so "
				"service_recv_tof() failed\n");
		return NULL;
	}
	ctf_msg(ctf_debug, client, "got past ctf_proto_stk_decode()\n");
	ctf_msg(ctf_debug, client, "return %p\n", cpsdr);
	return cpsdr;
}

int
service_send_tof(struct ctf_state *state, struct tof_msg *tof, int fd)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf, *cur_buf;
	size_t sz, cur_sz;
	ssize_t ret_sz;

	if (!(buf = ctf_proto_stk_encode(mpn_trace_objects, (union msg *)tof, &sz)))
		return RETVAL_FAILURE;
	/* This is an awkward enough pattern that the API should change. */
	cur_buf = buf;
	cur_sz = sz;
retry_send:
	ret_sz = write(fd, cur_buf, cur_sz);
	if (ret_sz == (ssize_t)cur_sz)
		retval = RETVAL_SUCCESS;
	else if (!ret_sz && !errno) { /* EOF */
		ctf_msg(ctf_alert, client, "other end closed connection\n");
		retval = RETVAL_SUCCESS;
		goto out_free_buf;
	} else if (!ret_sz && !errno_is_restart(errno)) {
		ctf_msg(ctf_alert, client, "write failed %d (%s)\n",
				errno, strerror(errno));
		goto out_free_buf;
	} else if (ret_sz >= 0) {
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
service_build_reply(struct ctf_state *state, struct tof_request *req)
{
	struct tof_msg *msg = NULL;

	if (to_queue_answer_request(&state->unix_io.in_queue, req, &msg) == svc_req_success)
		return msg;
	return NULL;
}

void
service_client_destroy(struct ctf_state *state, int fd)
{
	int k;

	(void)!shutdown(fd, SHUT_RDWR);
	(void)!close(fd);
	FD_CLR(fd, &state->state_fds);
	
	if (!!state->ux_io) {
		for (k = 0; k < state->nr_clients; ++k) {
			if (state->ux_io[k].fd == fd) {
				while (!g_queue_is_empty(&state->ux_io[k].in_queue))
					g_rc_box_release_full(to_dequeue(&state->ux_io[k].in_queue),
							      (GDestroyNotify)trace_object_free);
				while (!g_queue_is_empty(&state->ux_io[k].out_queue))
					g_rc_box_release_full(to_dequeue(&state->ux_io[k].out_queue),
							      (GDestroyNotify)trace_object_free);
				if (k < state->nr_clients - 1)
					state->ux_io[k] = state->ux_io[state->nr_clients - 1];
				break;
			}
		}
	}
	state->nr_clients--;
}

int
service_client_sock(struct ctf_state *state, struct pollfd *pollfd)
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
		tof = (struct tof_msg *)cpsdr->proto_stk_decode_result_body;
		/* It could be break, but the label's name is descriptive. */
		goto tof_msg_type_switch;
	default:
		ctf_msg(ctf_alert, client, "bad sdu_proto_num %d\n",
				cpsdr->sdu.sdu_proto_un.sdu_proto_num);
		/* Deliberate fall-through; more properly, the other
		 * cases are skipping over the log message from the
		 * default case. */
	case mpn_EKG_metrics:
	case mpn_data_points:
		union msg **msg_ref;
		cbor_item_t **cbor_ref;

		/* These protocols' CBOR contents aren't decoded. */
		tof = NULL;
		if (!cpsdr->proto_stk_decode_result_body)
			goto out_free_cpsdr;
		msg_ref = &cpsdr->proto_stk_decode_result_body;
		cbor_ref = (cbor_item_t **)msg_ref;
		ctf_cbor_decref(client, cbor_ref);
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
		ctf_msg(ctf_alert, client, "bad tof_msg_type %d\n",
				tof->tof_msg_type);
		goto out_free_cpsdr;
	}
out_free_cpsdr:
	cpsdr_free(cpsdr);
	return retval;
}
