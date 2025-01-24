#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include "c_trace_fwd.h"
#include "proto_stk.h"
#include "sdu.h"
#include "service.h"
#include "tof.h"

static struct tof_msg *
service_recv_tof(struct c_trace_fwd_state *state, int fd)
{
	struct tof_msg *tof = NULL;
	char *buf;
	ssize_t ret_sz;

	if (!(buf = calloc(1024, 1024)))
		return NULL;
retry_read:
	ret_sz = read(fd, buf, 1024*1024);
	if (ret_sz > 0)
		tof = ctf_proto_stk_decode(buf);
	else if (!ret_sz && errno == EAGAIN && errno == EWOULDBLOCK)
		goto retry_read;
	free(buf);
	return tof;
}

static int
service_send_tof(struct c_trace_fwd_state *state, struct tof_msg *tof, int fd)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf;
	struct sdu sdu;
	size_t buf_len;
	ssize_t ret_sz;

	buf = ctf_proto_stk_encode(tof);
	/* This is an awkward enough pattern that the API should change. */
	if (sdu_decode((uint32_t *)buf, &sdu))
		goto exit_free_buf;
	buf_len = sdu.sdu_len + 2*sizeof(uint32_t);
	ret_sz = write(fd, buf, buf_len);
	if (ret_sz != (ssize_t)buf_len)
		goto exit_free_buf;
	retval = RETVAL_SUCCESS;
exit_free_buf:
	free(buf);
	return retval;
}

static struct tof_msg *
service_build_reply(struct c_trace_fwd_state *state, struct tof_request *req)
{
	struct tof_msg *tof;
	struct tof_reply *reply;

	if (!(tof = calloc(1, sizeof(struct tof_msg))))
		return NULL;
	tof->tof_msg_type = tof_reply;
	reply = &tof->tof_msg_body.reply;
	reply->tof_nr_replies = req->tof_nr_obj;
	if (!(reply->tof_replies = calloc(req->tof_nr_obj, sizeof(struct trace_object *))))
		goto exit_tof_free;
	if (!to_dequeue_multi(state, &reply->tof_replies, &reply->tof_nr_replies))
		return tof;
exit_tof_free:
	tof_free(tof);
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
	struct tof_msg *tof, *tof_reply_msg;

	if (!!(pollfd->revents & (POLLERR|POLLHUP))) {
		service_client_destroy(state, pollfd->fd);
		return RETVAL_SUCCESS;
	}
	if (!(pollfd->revents & (POLLIN|POLLPRI)))
		return RETVAL_SUCCESS;
	if (!(tof = service_recv_tof(state, pollfd->fd)))
		return RETVAL_FAILURE;
	if (tof->tof_msg_type != tof_request)
		goto exit_free_tof;
	tof_reply_msg = service_build_reply(state, &tof->tof_msg_body.request);
	if (!tof_reply_msg)
		goto exit_free_tof;
	if (service_send_tof(state, tof_reply_msg, pollfd->fd))
		goto exit_free_reply_msg;
exit_free_reply_msg:
	tof_free(tof_reply_msg);
exit_free_tof:
	tof_free(tof);
	return retval;
}
