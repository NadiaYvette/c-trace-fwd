#include <cbor.h>
#include "c_trace_fwd.h"

void
ctf_string_start(void *ctx)
{
	(*cbor_empty_callbacks.string_start)(ctx);
}

void
ctf_string(void *ctx, cbor_data buf, uint64_t len)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.string)(ctx, buf, len);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_string((const char *)buf);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void
ctf_byte_string_start(void *ctx)
{
	(*cbor_empty_callbacks.byte_string_start)(ctx);
}

void
ctf_byte_string(void *ctx, cbor_data buf, uint64_t len)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.byte_string)(ctx, buf, len);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	/* Is this right? There's no cbor_build_byte_string() */
	state->item_tbl[pos] = cbor_build_string((const char *)buf);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}
