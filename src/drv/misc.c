#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv.h"

void ctf_undefined(void *ctx)
{
	(*cbor_empty_callbacks.undefined)(ctx);
}

void ctf_null(void *ctx)
{
	(*cbor_empty_callbacks.null)(ctx);
}

void ctf_boolean(void *ctx, bool val)
{
	struct c_trace_fwd_state *state = ctx;
	cbor_item_t *item;

	(*cbor_empty_callbacks.boolean)(ctx, val);
	if (!(item = cbor_build_bool(val)))
		return;
	if (ctf_stk_push(state, item))
		goto out_decref;
	return;
	ctf_stk_pop(state);
out_decref:
	cbor_decref(&item);
}

void ctf_indef_break(void *ctx)
{
	struct c_trace_fwd_state *state = ctx;
	cbor_item_t *item;

	(*cbor_empty_callbacks.indef_break)(ctx);
	if (!(item = ctf_stk_pop(state)))
		return;
	switch (cbor_typeof(item)) {
	case CBOR_TYPE_STRING:
	case CBOR_TYPE_ARRAY:
	case CBOR_TYPE_MAP:
	case CBOR_TYPE_BYTESTRING:
		if (!cbor_bytestring_is_indefinite(item))
			break;
	default:
	}
}

void ctf_tag(void *ctx, uint64_t val)
{
	struct c_trace_fwd_state *state = ctx;
	cbor_item_t *item;

	/* What does the tag get attached to? */
	(*cbor_empty_callbacks.tag)(ctx, val);
	if (!(item = cbor_new_tag(val)))
		return;
	if (ctf_stk_push(state, item))
		goto out_decref;
	return;
	ctf_stk_pop(state);
out_decref:
	cbor_decref(&item);
}
