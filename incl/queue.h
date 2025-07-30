#pragma once

#include "agency.h"
#include "svc_enum.h"

struct c_trace_fwd_state;
struct trace_object;
struct tof_msg;
struct tof_request;

struct queue {
	unsigned nr_to;
	struct trace_object **queue;
};

struct io_queue {
	struct queue in_queue, out_queue;
	int fd;
	enum agency agency;
};

struct trace_object *to_dequeue(struct queue *);
int to_dequeue_multi(struct queue *, struct trace_object ***, int, int *);
int to_enqueue(struct queue *, struct trace_object *);
int to_enqueue_multi(struct queue *, struct trace_object **, int);
bool to_queue_move(struct queue *, struct queue *, size_t);
enum svc_req_result
to_queue_answer_request(struct queue *,
		const struct tof_request *, struct tof_msg **);
