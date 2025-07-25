#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv.h"
#include "ctf_util.h"

void ctf_indef_array_start(void *ctx)
{
	struct c_trace_fwd_state *state = ctx;
	cbor_item_t *array;

	(*cbor_empty_callbacks.indef_array_start)(ctx);
	if (!(array = cbor_new_indefinite_array()))
		return;
	if (ctf_stk_push(state, array))
		ctf_cbor_decref(collection, &array);
}

void ctf_array_start(void *ctx, uint16_t len)
{
	struct c_trace_fwd_state *state = ctx;
	cbor_item_t *array;

	(*cbor_empty_callbacks.array_start)(ctx, len);
	if (!(array = cbor_new_definite_array(len)))
		return;
	if (ctf_stk_push(state, array))
		ctf_cbor_decref(collection, &array);
}

void ctf_indef_map_start(void *ctx)
{
	(*cbor_empty_callbacks.indef_map_start)(ctx);
}

void ctf_map_start(void *ctx, uint16_t len)
{
	(*cbor_empty_callbacks.array_start)(ctx, len);
}
