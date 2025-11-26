#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <sys/param.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "service.h"
#include "tof.h"

bool
to_queue_fillarray(struct trace_object ***dst, GQueue *src, size_t *nr)
{
	GQueue tmp = G_QUEUE_INIT;
	size_t k, nr_ret, nr_req = *nr;

	for (k = 0; k < nr_req; ++k) {
		if (g_queue_is_empty(src))
			break;
	}
	nr_ret = to_queue_move(&tmp, src, nr_req);
	if (!(*dst = calloc(nr_ret, sizeof(struct trace_object *))))
		goto out_restore_queue;
	for (k = 0; k < nr_ret; ++k)
		(*dst)[k] = g_queue_pop_head(&tmp);
	*nr = nr_ret;
	return true;
out_restore_queue:
	while (!g_queue_is_empty(&tmp))
		g_queue_push_tail(src, g_queue_pop_head(&tmp));
	return false;
}

bool
to_queue_putarray(GQueue *dst, struct trace_object **to, size_t nr)
{
	size_t k;

	for (k = 0; k < nr; ++k)
		g_queue_push_tail(dst, to[k]);
	return true;
}

size_t
to_queue_move(GQueue *dst, GQueue *src, size_t nr_requested)
{
	size_t nr_moved;
	gpointer datum;

	for (nr_moved = 0; nr_moved < nr_requested; ++nr_moved) {
		if (g_queue_is_empty(src))
			break;
		if (!(datum = g_queue_pop_head(src)))
			break;
		g_queue_push_tail(dst, datum);
	}
	return nr_moved;
}

int
to_enqueue(GQueue *queue, struct trace_object *to)
{
	if (to)
		g_rc_box_acquire(to);
	g_queue_push_tail(queue, to);
	return RETVAL_SUCCESS;
}

struct trace_object *
to_dequeue(GQueue *queue)
{
	return g_queue_pop_head(queue);
}

enum svc_req_result
to_queue_answer_request( GQueue *queue
		       , const struct tof_request *request
		       , struct tof_msg **reply_msg)
{
	struct tof_msg *msg;
	struct trace_object ***to;
	size_t req_obj;

	if (!reply_msg)
		return svc_req_failure;
	if (request->tof_blocking && g_queue_is_empty(queue))
		return svc_req_must_block;
	if (!(msg = g_rc_box_new0(struct tof_msg)))
		return svc_req_failure;
	req_obj = request->tof_nr_obj;
	msg->tof_msg_type = tof_reply;
	to = &msg->tof_msg_body.reply.tof_replies;
	if (!to_queue_fillarray(to, queue, &req_obj)) {
		ctf_msg(ctf_alert, queue,
				"to_dequeue_fillarray() failed!\n");
		goto out_free_replies;
	}
	msg->tof_msg_body.reply.tof_nr_replies = req_obj;
	*reply_msg = msg;
	return svc_req_success;
out_free_replies:
	tof_free(msg);
	return svc_req_failure;
}

bool
io_queue_init(struct io_queue *ioq, int fd)
{
	enum mini_protocol_num mpn;

	g_queue_init(&ioq->in_queue);
	g_queue_init(&ioq->out_queue);
	ioq->fd = fd;
	for (mpn = MPN_MIN; mpn <= MPN_MAX; ++mpn) {
		if (!MPN_VALID(mpn))
			continue;
		ioq->agencies[mpn - MPN_MIN] = relative_agency_they_have;
	}
	return true;
}

void
io_queue_show_agencies(struct io_queue *queue)
{
	enum mini_protocol_num mpn;
	const char boundary[]
		= "========================================"
		  "========================================";

	ctf_msg(ctf_debug, queue, "%s\n", boundary);
	for (mpn = MPN_MIN; mpn <= MPN_MAX; ++mpn) {
		enum relative_agency agency;
		const char *mpn_str, *agency_str;

		if (!io_queue_agency_get(queue, mpn, &agency))
			break;
		mpn_str = mini_protocol_string(mpn);
		agency_str = relative_agency_string(agency);
		ctf_msg(ctf_debug, queue, "[%s] = %s,\n", mpn_str, agency_str);
	}
	ctf_msg(ctf_debug, queue, "%s\n", boundary);
}
