#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "service.h"
#include "tof.h"

struct trace_object *
to_dequeue(struct queue *queue)
{
	struct trace_object *to, **new_queue;

	if (queue->nr_to == 0 || queue->queue == NULL)
		return NULL;
	to = queue->queue[0];
	memmove(&queue->queue[0], &queue->queue[1], (queue->nr_to - 1) * sizeof(struct trace_object *));
	new_queue = reallocarray(queue->queue, queue->nr_to - 1, sizeof(struct trace_object *));
	if (!!new_queue) {
		queue->queue = new_queue;
		queue->nr_to--;
		return to;
	}
	memmove(&queue->queue[1], &queue->queue[0], (queue->nr_to - 1) * sizeof(struct trace_object *));
	queue->queue[0] = to;
	return NULL;
}

int
to_dequeue_multi(struct queue *queue, struct trace_object ***to, int req_len, int *n)
{
	int nr_to, nr_q;
	struct trace_object **new_q;

	ctf_msg(queue, "req_len = %d, *n = %d, queue->nr_to = %d\n",
			req_len, *n, queue->nr_to);
	nr_to = MIN(req_len, queue->nr_to);
	nr_q  = queue->nr_to - nr_to;
	if (!nr_to || !queue->queue) {
		free(*to);
		*to = NULL;
		*n = 0;
		return RETVAL_SUCCESS;
	} else if (nr_to < req_len) {
		struct trace_object **new_to;

		if (!!queue->queue)
			new_to = reallocarray(*to, nr_to, sizeof(struct trace_object *));
		else
			new_to = calloc(nr_to, sizeof(struct trace_object *));
		if (!new_to) {
			ctf_msg(queue, "reallocarray()/calloc() failed!\n");
			return RETVAL_FAILURE;
		}
		*to = new_to;
		*n = nr_to;
	}
	memccpy(*to, queue->queue, nr_to, sizeof(struct trace_object *));
	if (!nr_q && 0) {
		free(queue->queue);
		queue->queue = NULL;
		queue->nr_to    = 0;
		return RETVAL_SUCCESS;
	}
	memmove(&queue->queue[0], &queue->queue[nr_to],
		nr_q * sizeof(struct trace_object *));
	if (!!nr_q)
		new_q = reallocarray(queue->queue, nr_q,
					sizeof(struct trace_object *));
	else {
		free(queue->queue);
		new_q = NULL;
	}
	if (!!new_q || (!nr_q && !new_q)) {
		queue->queue = new_q;
		queue->nr_to -= nr_to;
		return RETVAL_SUCCESS;
	}
	memmove(&queue->queue[nr_to], &queue->queue[0],
		nr_q * sizeof(struct trace_object *));
	memccpy(queue->queue, to, nr_to, sizeof(struct trace_object *));
	memset(*to, 0, (*n) * sizeof(struct trace_object *));
	ctf_msg(queue, "fell through! queue->nr_to = %d, nr_to = %d, *n = %d\n",
			queue->nr_to, nr_to, *n);
	return RETVAL_FAILURE;
}

int
to_enqueue(struct queue *queue, struct trace_object *to)
{
	struct trace_object **new_queue;

	new_queue = reallocarray(queue->queue, queue->nr_to + 1, sizeof(struct trace_object *));
	if (!new_queue)
		return RETVAL_FAILURE;
	queue->queue = new_queue;
	queue->nr_to++;
	queue->queue[queue->nr_to - 1] = to;
	return RETVAL_SUCCESS;
}

int
to_enqueue_multi(struct queue *queue, struct trace_object **to, int n)
{
	struct trace_object **new_queue;

	ctf_msg(queue, "entering to_enqueue_multi()\n");
	if (!(new_queue = reallocarray(queue->queue, queue->nr_to + n, sizeof(struct trace_object *)))) {
		ctf_msg(queue, "reallocarray() failed, n = %d, nmemb = %zd, size = %zd\n",
				n, (size_t)(queue->nr_to + n), sizeof(struct trace_object *));
		return RETVAL_FAILURE;
	}
	memccpy(&new_queue[queue->nr_to], to, n, sizeof(struct trace_object *));
	queue->queue = new_queue;
	queue->nr_to += n;
	ctf_msg(queue, "to_enqueue_multi() succeeded\n");
	return RETVAL_SUCCESS;
}

enum svc_req_result
to_queue_answer_request( struct queue *queue
		       , const struct tof_request *request
		       , struct tof_msg **reply_msg)
{
	struct tof_msg *msg;
	struct trace_object ***to;
	int *n, req_obj;

	if (!reply_msg)
		return svc_req_failure;
	if (request->tof_blocking && !queue->nr_to)
		return svc_req_must_block;
	if (!(msg = calloc(1, sizeof(struct tof_msg))))
		return svc_req_failure;
	req_obj = request->tof_nr_obj;
	msg->tof_msg_type = tof_reply;
	to = &msg->tof_msg_body.reply.tof_replies;
	if (!(*to = calloc(req_obj, sizeof(struct trace_object *)))) {
		free(msg);
		return svc_req_failure;
	}
	n = &msg->tof_msg_body.reply.tof_nr_replies;
	if (to_dequeue_multi(queue, to, req_obj, n) != RETVAL_SUCCESS) {
		ctf_msg(queue, "to_dequeue_multi() failed!\n");
		goto out_free_replies;
	}
	*reply_msg = msg;
	return svc_req_success;
out_free_replies:
	free(msg->tof_msg_body.reply.tof_replies);
/* out_free_msg: */
	free(msg);
	return svc_req_failure;
}
