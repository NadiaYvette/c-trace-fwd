#include <cbor.h>
#include "c_trace_fwd.h"

void
ctf_float2(void *ctx, float val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.float2)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_float2(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void
ctf_float4(void *ctx, float val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.float4)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_float4(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void
ctf_float8(void *ctx, double val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.float8)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_float8(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}
