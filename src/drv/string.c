#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv.h"
#include "ctf_util.h"

void ctf_string_start(void *ctx)
{
	struct c_trace_fwd_state *state = ctx;
	cbor_item_t *item;

	(*cbor_empty_callbacks.string_start)(ctx);
	if (!(item = cbor_new_indefinite_string()))
		return;
	if (ctf_stk_push(state, item))
		cbor_decref(&item);
}

void ctf_string(void *ctx, cbor_data buf, uint64_t len)
{
	cbor_item_t *chunk, *stack_top;
	struct c_trace_fwd_state *state = ctx;

	(*cbor_empty_callbacks.string)(ctx, buf, len);
	if (!(chunk = cbor_build_string((const char *)buf)))
		return;
	if (ctf_tbl_push(state, chunk))
		goto out_decref;
	stack_top = state->stack[state->stack_top];
	if (cbor_string_is_definite(stack_top))
		return;
	if (cbor_string_add_chunk(stack_top, chunk))
		return;
	ctf_tbl_pop(state);
out_decref:
	ctf_msg(drv, "failed adding cbor bytestring chunk \"%s\"\n", buf);
	cbor_decref(&chunk);
}

void ctf_byte_string_start(void *ctx)
{
	struct c_trace_fwd_state *state = ctx;
	cbor_item_t *item;

	(*cbor_empty_callbacks.byte_string_start)(ctx);
	if (!(item = cbor_new_indefinite_bytestring()))
		return;
	if (ctf_stk_push(state, item))
		cbor_decref(&item);
}

void ctf_byte_string(void *ctx, cbor_data buf, uint64_t len)
{
	cbor_item_t *chunk, *stack_top;
	struct c_trace_fwd_state *state = ctx;

	(*cbor_empty_callbacks.byte_string)(ctx, buf, len);
	if (!(chunk = cbor_build_bytestring(buf, len)))
		return;
	if (!ctf_tbl_push(state, chunk))
		goto out_decref;
	stack_top = state->stack[state->stack_top];
	if (cbor_string_is_definite(stack_top))
		return;
	if (cbor_bytestring_add_chunk(stack_top, chunk))
		return;
	ctf_tbl_pop(state);
out_decref:
	ctf_msg(drv, "failed adding cbor bytestring chunk \"%s\"\n", buf);
	cbor_decref(&chunk);
}
