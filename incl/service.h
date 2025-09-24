#pragma once

#include "svc_enum.h"

struct pollfd;

struct ctf_conf;
struct ctf_state;
struct tof_msg;
struct tof_request;
struct trace_object;
struct ctf_proto_stk_decode_result;

struct ctf_proto_stk_decode_result *service_recv_tof(struct ctf_state *, int);
int service_send_tof(struct ctf_state *, struct tof_msg *, int);

void service_client_destroy(struct ctf_state *, int);
int service_client_sock(struct ctf_state *, struct pollfd *);
enum svc_result service_unix_sock(struct ctf_state *, struct pollfd *);
int service_ux_sock(struct ctf_state *);
int service_loop(struct ctf_state *, struct ctf_conf *);
bool service_thread_spawn(struct ctf_conf *, struct ctf_state *);
