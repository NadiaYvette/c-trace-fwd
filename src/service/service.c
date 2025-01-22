#include <cbor.h>
#include <cbor/data.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include "c_trace_fwd.h"
#include "proto_stk.h"
#include "sdu.h"
#include "tof.h"

static int
service_ux_sock(struct c_trace_fwd_state *state)
{
	int new_fd = accept(state->ux_sock_fd, NULL, NULL);

	if (new_fd < 0)
		return RETVAL_FAILURE;
	state->nr_clients++;
	FD_SET(new_fd, &state->state_fds);
	return RETVAL_SUCCESS;
}

static int
to_enqueue(struct c_trace_fwd_state *state, struct trace_object *to)
{
	struct trace_object **new_queue;

	new_queue = reallocarray(state->to_queue, state->nr_to + 1, sizeof(struct trace_object));
	if (!new_queue)
		return RETVAL_FAILURE;
	state->to_queue = new_queue;
	state->nr_to++;
	state->to_queue[state->nr_to - 1] = to;
	return RETVAL_SUCCESS;
}

static struct trace_object *
to_dequeue(struct c_trace_fwd_state *state)
{
	struct trace_object *to, **new_queue;

	to = state->to_queue[0];
	memmove(&state->to_queue[0], &state->to_queue[1], (state->nr_to - 1) * sizeof(struct trace_object *));
	new_queue = reallocarray(state->to_queue, state->nr_to - 1, sizeof(struct trace_object *));
	if (!!new_queue) {
		state->to_queue = new_queue;
		state->nr_to--;
		return to;
	}
	memmove(&state->to_queue[1], &state->to_queue[0], (state->nr_to - 1) * sizeof(struct trace_object *));
	state->to_queue[0] = to;
	return NULL;
}

static int
to_dequeue_multi(struct c_trace_fwd_state *state, struct trace_object **to, int n)
{
	int nr_to = MIN(n, state->nr_to);
	struct trace_object **new_to;

	if (!nr_to)
		return RETVAL_FAILURE;
	memccpy(to, state->to_queue, nr_to, sizeof(struct trace_object *));
	memmove(&state->to_queue[0], &state->to_queue[nr_to],
		(state->nr_to - nr_to) * sizeof(struct trace_object *));
	new_to = reallocarray(state->to_queue, state->nr_to - nr_to,
				sizeof(struct trace_object *));
	if (!!new_to) {
		state->to_queue = new_to;
		state->nr_to -= nr_to;
		return RETVAL_SUCCESS;
	}
	memmove(&state->to_queue[nr_to], &state->to_queue[0],
		(state->nr_to - nr_to) * sizeof(struct trace_object));
	memccpy(state->to_queue, to, nr_to, sizeof(struct trace_object *));
	memset(to, 0, nr_to * sizeof(struct trace_object *));
	return RETVAL_FAILURE;
}

static int
service_unix_sock(struct c_trace_fwd_state *state)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf;
	ssize_t ret_sz;
	struct tof_msg *tof;

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
	retval = RETVAL_SUCCESS;
exit_free_buf:
	free(buf);
	return retval;
}

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
	if (!!(reply->tof_replies = calloc(req->tof_nr_obj, sizeof(struct trace_object *))))
		return tof;
	free(tof);
	return NULL;
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

static int
service_client_sock(struct c_trace_fwd_state *state, struct pollfd *pollfd)
{
	int reply_nr_to, retval = RETVAL_FAILURE;
	unsigned char *buf, *reply_buf;
	ssize_t ret_sz;
	struct tof_reply *reply;
	struct tof_msg *tof, *tof_reply_msg;
	struct tof_request *req;
	struct sdu reply_sdu;

	if (!!(pollfd->revents & (POLLERR|POLLHUP))) {
		(void)!shutdown(pollfd->fd, SHUT_RDWR);
		(void)!close(pollfd->fd);
		FD_CLR(pollfd->fd, &state->state_fds);
		state->nr_clients--;
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

	if (!(buf = calloc(1024, 1024)))
		return RETVAL_FAILURE;
retry_read:
	ret_sz = read(pollfd->fd, buf, 1024*1024);
	if (ret_sz <= 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			goto exit_free_buf;
		errno = 0;
		goto retry_read;
	}
	if (!(tof = ctf_proto_stk_decode(buf)))
		goto exit_free_buf;
	req = &tof->tof_msg_body.request;
	tof_reply_msg = malloc(sizeof(struct tof_msg));
	if (!tof_reply_msg)
		goto exit_free_tof;
	tof_reply_msg->tof_msg_type = tof_reply;
	reply_nr_to = MIN(req->tof_nr_obj, state->nr_to);
	reply = &tof_reply_msg->tof_msg_body.reply;
	reply->tof_nr_replies = reply_nr_to;
	reply->tof_replies = calloc(reply_nr_to, sizeof(struct trace_object *));
	if (!reply->tof_replies)
		goto exit_free_tof;
	if (to_dequeue_multi(state, reply->tof_replies, reply_nr_to))
		goto exit_free_reply_msg;
	if (!(reply_buf = ctf_proto_stk_encode(tof_reply_msg)))
		goto exit_free_reply_msg;
	if (sdu_decode((uint32_t *)reply_buf, &reply_sdu))
		goto exit_free_tof;
	ret_sz = write(pollfd->fd, reply_buf, reply_sdu.sdu_len + 2 * sizeof(uint32_t));
	if (ret_sz < 0)
		goto exit_free_reply_buf;
	retval = RETVAL_SUCCESS;
exit_free_reply_buf:
	free(reply_buf);
exit_free_reply_msg:
	tof_free(tof_reply_msg);
exit_free_tof:
	tof_free(tof);
exit_free_buf:
	free(buf);
	return retval;
}

static int
service_loop_core(struct c_trace_fwd_state *state)
{
	int nr_ready, k, m, retval = RETVAL_FAILURE;
	struct pollfd *pollfds;

	if (pthread_mutex_lock(&state->state_lock))
		return RETVAL_FAILURE;
	pollfds = calloc(state->nr_clients + 2, sizeof(struct pollfd));
	if (!pollfds)
		goto exit_unlock;
	for (k = m = 0; k < FD_SETSIZE; ++k) {
		if (!FD_ISSET(k, &state->state_fds))
			continue;
		pollfds[m].fd = k;
		pollfds[m].events = POLLIN|POLLPRI|POLLOUT|POLLERR|POLLHUP;
		++m;
	}
	nr_ready = poll(pollfds, state->nr_clients + 2, 0);
	if (nr_ready < 0) {
		goto exit_free_pollfds;
	}
	for (k = 0; k < state->nr_clients + 2; ++k) {
		if (!pollfds[k].revents)
			continue;
		else if (pollfds[k].fd == state->ux_sock_fd) {
			if (service_ux_sock(state))
				goto exit_free_pollfds;
		} else if (pollfds[k].fd == state->unix_sock_fd) {
			if (service_unix_sock(state))
				goto exit_free_pollfds;
		} else if (service_client_sock(state, &pollfds[k]))
			goto exit_free_pollfds;
	}
exit_free_pollfds:
	free(pollfds);
exit_unlock:
	(void)!pthread_mutex_unlock(&state->state_lock);
	return retval;
}

int
service_loop(struct c_trace_fwd_state *state, struct c_trace_fwd_conf *conf)
{
	int retval = RETVAL_FAILURE;

	while (1) {
		char *buf, *reply_buf;
		ssize_t bytes_returned;
		size_t buf_len, buf_chunksz = 1024, buf_chunks = 1024;
		struct sdu sdu;
		struct tof_msg *tof_msg;

		buf_len = buf_chunks * buf_chunksz;
		buf = calloc(buf_chunks, buf_chunksz);
retry_read:
		if (pthread_mutex_lock(&state->state_lock))
			goto exit_failure;
		bytes_returned = read(state->unix_sock_fd, buf, buf_len);
		if (bytes_returned <= 0) {
			(void)!pthread_mutex_unlock(&state->state_lock);
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				goto exit_failure;
			errno = 0;
			goto retry_read;
		}
		tof_msg = ctf_proto_stk_decode(buf);
		reply_buf = ctf_proto_stk_encode(tof_msg);
		/* SDU len field value excludes header */
		sdu_decode((uint32_t *)reply_buf, &sdu);
		write(state->ux_sock_fd, reply_buf, sdu.sdu_len + 2 * sizeof(uint32_t));
		(void)!pthread_mutex_unlock(&state->state_lock);
		if (buf == NULL)
			goto exit_failure;
		free(buf);
	}
	retval = RETVAL_SUCCESS;
exit_failure:
	return retval;
}
