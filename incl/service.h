#pragma once

struct pollfd;

struct c_trace_fwd_conf;
struct c_trace_fwd_state;
struct trace_object;

struct trace_object *to_dequeue(struct c_trace_fwd_state *);
int to_dequeue_multi(struct c_trace_fwd_state *, struct trace_object ***, int *);
int to_enqueue(struct c_trace_fwd_state *, struct trace_object *);
int to_enqueue_multi(struct c_trace_fwd_state *, struct trace_object **, int);

void service_client_destroy(struct c_trace_fwd_state *, int);
int service_client_sock(struct c_trace_fwd_state *, struct pollfd *);
int service_unix_sock(struct c_trace_fwd_state *);
int service_ux_sock(struct c_trace_fwd_state *);
int service_loop(struct c_trace_fwd_state *, struct c_trace_fwd_conf *);
