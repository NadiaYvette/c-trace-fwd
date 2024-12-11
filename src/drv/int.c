#include <cbor.h>
#include "c_trace_fwd.h"

void ctf_uint8(void *ctx, uint8_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.uint8)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_uint8(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void ctf_uint16(void *ctx, uint16_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.uint16)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_uint16(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void ctf_uint32(void *ctx, uint32_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.uint32)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_uint32(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void ctf_uint64(void *ctx, uint64_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.uint64)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_uint64(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void ctf_negint8(void *ctx, uint8_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.negint8)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_negint8(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void ctf_negint16(void *ctx, uint16_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.negint16)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_negint16(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void ctf_negint32(void *ctx, uint32_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.negint32)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_negint32(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void ctf_negint64(void *ctx, uint64_t val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.negint64)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_negint64(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}
