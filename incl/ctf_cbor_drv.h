#pragma once

#include <cbor.h>

struct c_trace_fwd_state;

extern const struct cbor_callbacks ctf_cbor_drv;
cbor_item_t *ctf_stk_pop(struct c_trace_fwd_state *);
int ctf_stk_push(struct c_trace_fwd_state *, cbor_item_t *);
