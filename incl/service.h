#pragma once

struct pollfd;

struct c_trace_fwd_conf;
struct c_trace_fwd_state;
struct tof_msg;
struct tof_request;
struct trace_object;

struct trace_object *to_dequeue(struct c_trace_fwd_state *);
int to_dequeue_multi(struct c_trace_fwd_state *, struct trace_object ***, int *);
int to_enqueue(struct c_trace_fwd_state *, struct trace_object *);
int to_enqueue_multi(struct c_trace_fwd_state *, struct trace_object **, int);

enum svc_req_result {
	svc_req_must_block,
	svc_req_success,
	svc_req_none_available,
	svc_req_failure,
};

enum svc_req_result
to_queue_answer_request(struct c_trace_fwd_state *,
		const struct tof_request *, struct tof_msg **);

void service_client_destroy(struct c_trace_fwd_state *, int);
int service_client_sock(struct c_trace_fwd_state *, struct pollfd *);
int service_unix_sock(struct c_trace_fwd_state *);
int service_ux_sock(struct c_trace_fwd_state *);
int service_loop(struct c_trace_fwd_state *, struct c_trace_fwd_conf *);
