#include <cbor.h>
#include <cbor/data.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
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
service_unix_sock(struct c_trace_fwd_state *state)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf;
	ssize_t ret_sz;
	cbor_item_t *item;
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
	if (!(item = cbor_load(buf, ret_sz, NULL)))
		goto exit_free_buf;
	if (!(tof = tof_decode(item)))
		goto exit_cbor_decref;
	if (tof->tof_msg_type != tof_reply)
		goto exit_cbor_decref;
	retval = RETVAL_SUCCESS;
exit_cbor_decref:
	cbor_decref(&item);
exit_free_buf:
	free(buf);
	return retval;
}

static int
service_client_sock(struct c_trace_fwd_state *state, struct pollfd *pollfd)
{
	int k, reply_nr_to, retval = RETVAL_FAILURE;
	unsigned char *buf, *reply_buf;
	ssize_t ret_sz;
	struct tof_reply *reply;
	struct tof_msg *tof, *tof_reply;
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
	if (tof->tof_msg_type != tof_request)
		goto exit_free_tof;
	req = &tof->tof_msg_body.request;
	tof_reply = malloc(sizeof(struct tof_msg));
	if (!tof_reply)
		goto exit_free_tof;
	tof_reply->tof_msg_type = tof_reply;
	reply_nr_to = MIN(req->tof_nr_obj, state->nr_to);
	reply = &tof_reply->tof_msg_body.reply;
	reply->tof_nr_replies = reply_nr_to;
	reply->tof_replies = calloc(reply_nr_to, sizeof(struct trace_object *));
	for (k = 0; k < reply_nr_to; ++k)
		reply->tof_replies[k] = to_dequeue(state);
	reply_buf = ctf_proto_stk_encode(tof_reply);
	if (sdu_decode((uint32_t *)reply_buf, &reply_sdu))
		goto exit_free_reply_buf;
	ret_sz = write(pollfd->fd, reply_buf, reply_sdu.sdu_len + 2 * sizeof(uint32_t));
	retval = RETVAL_SUCCESS;
exit_free_reply_buf:
	free(reply_buf);
exit_free_reply:
	/* this mangles the ordering, but it's an error case anyway */
	for (k = reply_nr_to - 1; k >= 0; --k) {
		if (!reply->tof_replies[k])
			continue;
		to_enqueue(state, reply->tof_replies[k]);
	}
exit_free_tof:
	if (tof->tof_msg_type == tof_reply)
		free(tof->tof_msg_body.reply.tof_replies);
	free(tof);
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
