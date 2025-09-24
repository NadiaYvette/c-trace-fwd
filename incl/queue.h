#pragma once

#include <glib.h>
#include "agency.h"
#include "mpn.h"
#include "svc_enum.h"

struct ctf_state;
struct trace_object;
struct tof_msg;
struct tof_request;

struct io_queue {
	GQueue in_queue, out_queue;
	int fd;
	enum agency agencies[MPN_NR];
	bool reply_pending;
};

struct trace_object *to_dequeue(GQueue *);
int to_enqueue(GQueue *, struct trace_object *);
size_t to_queue_move(GQueue *, GQueue *, size_t);
bool to_queue_fillarray(struct trace_object ***, GQueue *, size_t *);
bool to_queue_putarray(GQueue *, struct trace_object **, size_t);
enum svc_req_result
to_queue_answer_request(GQueue *,
		const struct tof_request *, struct tof_msg **);
bool io_queue_init(struct io_queue *, int);
enum agency io_queue_agency_get(struct io_queue *, enum mini_protocol_num);
void io_queue_agency_set(struct io_queue *, enum mini_protocol_num, enum agency);
bool io_queue_agency_any_local(struct io_queue *);
bool io_queue_agency_all_nonlocal(struct io_queue *);
