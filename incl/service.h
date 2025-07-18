#pragma once

struct pollfd;

struct c_trace_fwd_conf;
struct c_trace_fwd_state;
struct tof_msg;
struct tof_request;
struct trace_object;
struct ctf_proto_stk_decode_result;

struct ctf_proto_stk_decode_result *service_recv_tof(struct c_trace_fwd_state *, int);
int service_send_tof(struct c_trace_fwd_state *, struct tof_msg *, int);

struct trace_object *to_dequeue(struct c_trace_fwd_state *);
int to_dequeue_multi(struct c_trace_fwd_state *, struct trace_object ***, int, int *);
int to_enqueue(struct c_trace_fwd_state *, struct trace_object *);
int to_enqueue_multi(struct c_trace_fwd_state *, struct trace_object **, int);

enum svc_result {
	svc_progress_fail = -1,
	svc_progress_none =  0,
	svc_progress_recv =  1,
	svc_progress_send =  2,
};

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
enum svc_result service_unix_sock(struct c_trace_fwd_state *, struct pollfd *);
int service_ux_sock(struct c_trace_fwd_state *);
int service_loop(struct c_trace_fwd_state *, struct c_trace_fwd_conf *);
