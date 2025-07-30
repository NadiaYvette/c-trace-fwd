#pragma once

#include "svc_enum.h"

struct pollfd;

struct c_trace_fwd_conf;
struct c_trace_fwd_state;
struct tof_msg;
struct tof_request;
struct trace_object;
struct ctf_proto_stk_decode_result;

struct ctf_proto_stk_decode_result *service_recv_tof(struct c_trace_fwd_state *, int);
int service_send_tof(struct c_trace_fwd_state *, struct tof_msg *, int);

void service_client_destroy(struct c_trace_fwd_state *, int);
int service_client_sock(struct c_trace_fwd_state *, struct pollfd *);
enum svc_result service_unix_sock(struct c_trace_fwd_state *, struct pollfd *);
int service_ux_sock(struct c_trace_fwd_state *);
int service_loop(struct c_trace_fwd_state *, struct c_trace_fwd_conf *);
