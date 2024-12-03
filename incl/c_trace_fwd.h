#pragma once

#define RETVAL_SUCCESS EXIT_SUCCESS
#define RETVAL_FAILURE EXIT_FAILURE

struct c_trace_fwd_conf {};
struct c_trace_fwd_state {};

int setup_conf(struct c_trace_fwd_conf **, int, char *[]);
int setup_state(struct c_trace_fwd_state **, struct c_trace_fwd_conf *);
int service_loop(struct c_trace_fwd_state *, struct c_trace_fwd_conf *);
void teardown_state(struct c_trace_fwd_state **);
void teardown_conf(struct c_trace_fwd_conf **);
