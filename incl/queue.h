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

struct queue_pair {
	struct queue in_queue, out_queue;
};

struct queue_io_point {
	struct queue_pair queue_pair;
	int fd;
	enum agency agency;
};

struct trace_object *to_dequeue(struct queue *);
int to_dequeue_multi(struct queue *, struct trace_object ***, int, int *);
int to_enqueue(struct queue *, struct trace_object *);
int to_enqueue_multi(struct queue *, struct trace_object **, int);
enum svc_req_result
to_queue_answer_request(struct queue *,
		const struct tof_request *, struct tof_msg **);
