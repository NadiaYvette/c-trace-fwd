#include <stdlib.h>
#include <string.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv_priv.h"

const struct cbor_callbacks ctf_cbor_drv = {
	.uint8 = ctf_uint8,
	.uint16 = ctf_uint16,
	.uint32 = ctf_uint32,
	.uint64 = ctf_uint64,
	.negint8 = ctf_negint8,
	.negint16 = ctf_negint16,
	.negint32 = ctf_negint32,
	.negint64 = ctf_negint64,
	.byte_string_start = ctf_byte_string_start,
	.byte_string = ctf_byte_string,
	.string = ctf_string,
	.string_start = ctf_string_start,
	.indef_array_start = ctf_indef_array_start,
	.array_start = ctf_array_start,
	.indef_map_start = ctf_indef_map_start,
	.map_start = ctf_map_start,
	.tag = ctf_tag,
	.float2 = ctf_float2,
	.float4 = ctf_float4,
	.float8 = ctf_float8,
	.undefined = ctf_undefined,
	.null = ctf_null,
	.boolean = ctf_boolean,
	.indef_break = ctf_indef_break,
};

cbor_item_t *ctf_stk_pop(struct c_trace_fwd_state *state)
{
	cbor_item_t *item;

	if (state->stack_top < 0)
		return NULL;
	item = state->stack[state->stack_top];
	state->stack_top--;
	return item;
}

int ctf_stk_grow(struct c_trace_fwd_state *state)
{
	size_t new_sz = 2 * state->stack_sz;
	cbor_item_t **new_stk;

	new_stk = calloc(new_sz, sizeof(cbor_item_t *));
	if (!new_stk)
		return RETVAL_FAILURE;
	memcpy(new_stk, state->stack, state->stack_sz * sizeof(cbor_item_t *));
	free(state->stack);
	state->stack = new_stk;
	state->stack_sz = new_sz;
	return RETVAL_SUCCESS;
}

int ctf_stk_push(struct c_trace_fwd_state *state, cbor_item_t *item)
{
	int retval = RETVAL_FAILURE;
	size_t top = state->stack_top;

	if (top + 1 >= state->stack_sz && (retval = ctf_stk_grow(state)))
		return retval;
	state->stack[top] = item;
	state->stack_top++;
	return RETVAL_SUCCESS;
}

int ctf_stk_top_append(struct c_trace_fwd_state *state, cbor_item_t *item)
{
	int retval = RETVAL_FAILURE;
	cbor_item_t *top;

	if (state->stack_top < 0)
		return RETVAL_FAILURE;
	top = state->stack[state->stack_top];
	switch (cbor_typeof(top)) {
	case CBOR_TYPE_BYTESTRING:
		if (cbor_bytestring_add_chunk(top, item))
			retval = RETVAL_SUCCESS;
		break;
	case CBOR_TYPE_STRING:
		if (cbor_string_add_chunk(top, item))
			retval = RETVAL_SUCCESS;
		break;
	case CBOR_TYPE_ARRAY:
		if (cbor_array_push(top, item))
			retval = RETVAL_SUCCESS;
		break;
	case CBOR_TYPE_MAP:
		cbor_item_t *key, *val;
		struct cbor_pair pair;

		if (state->stack_top < 2)
			break;
		val = ctf_stk_pop(state);
		key = ctf_stk_pop(state);
		pair.key = key;
		pair.value = val;
		if (cbor_map_add(top, pair))
			retval = RETVAL_SUCCESS;
		break;
	case CBOR_TYPE_TAG:
	default:
		break;
	}
	return retval;
}
