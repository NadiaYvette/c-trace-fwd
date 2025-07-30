#pragma once

#include <cbor.h>

struct ctf_stk_state;

extern const struct cbor_callbacks ctf_cbor_drv;
cbor_item_t *ctf_stk_pop(struct ctf_stk_state *);
int ctf_stk_push(struct ctf_stk_state *, cbor_item_t *);
