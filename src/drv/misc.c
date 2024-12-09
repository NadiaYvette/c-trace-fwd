#include <cbor.h>
#include "c_trace_fwd.h"

int
ctf_tbl_expand(struct c_trace_fwd_state *state)
{
	size_t new_tbl_sz, item_tbl_sz = state->item_tbl_sz;
	cbor_item_t **item_tbl, **new_tbl;
	int retval = RETVAL_FAILURE;

	new_tbl_sz = 2*item_tbl_sz;
	new_tbl = calloc(new_tbl_sz, sizeof(cbor_item_t *));
	if (!new_tbl)
		goto exit_failure;
	retval = RETVAL_SUCCESS;
	item_tbl = state->item_tbl;
	memcpy(new_tbl, item_tbl, item_tbl_sz * sizeof(cbor_item_t *));
	state->item_tbl = new_tbl;
	state->item_tbl_sz = new_tbl_sz;
	free(item_tbl);
exit_failure:
	return retval;
}

void
ctf_undefined(void *ctx)
{
	(*cbor_empty_callbacks.undefined)(ctx);
}

void
ctf_null(void *ctx)
{
	(*cbor_empty_callbacks.null)(ctx);
}

void
ctf_boolean(void *ctx, bool val)
{
	struct c_trace_fwd_state *state = ctx;
	size_t pos;

	(*cbor_empty_callbacks.boolean)(ctx, val);
	pos = state->item_tbl_pos;
	if (pos + 1 < state->item_tbl_sz && ctf_tbl_expand(state))
		return;
	state->item_tbl[pos] = cbor_build_bool(val);
	if (!state->item_tbl[pos])
		return;
	state->item_tbl_pos++;
}

void
ctf_indef_break(void *ctx)
{
	(*cbor_empty_callbacks.indef_break)(ctx);
}

void
ctf_tag(void *ctx, uint64_t val)
{
	/* What does the tag get attached to? */
	(*cbor_empty_callbacks.tag)(ctx, val);
}
