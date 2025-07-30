#pragma once

#include "svc_enum.h"

struct c_trace_fwd_state;
struct trace_object;
struct tof_msg;
struct tof_request;

struct queue {
	unsigned nr_to;
	struct trace_object **queue;
	int fd;
};

struct trace_object *to_dequeue(struct c_trace_fwd_state *);
int to_dequeue_multi(struct c_trace_fwd_state *, struct trace_object ***, int, int *);
int to_enqueue(struct c_trace_fwd_state *, struct trace_object *);
int to_enqueue_multi(struct c_trace_fwd_state *, struct trace_object **, int);
enum svc_req_result
to_queue_answer_request(struct c_trace_fwd_state *,
		const struct tof_request *, struct tof_msg **);
