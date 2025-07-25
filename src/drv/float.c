#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv.h"
#include "ctf_util.h"

void ctf_float2(void *ctx, float val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.float2)(ctx, val);
	if (!!(item = cbor_build_float2(val)))
		ctf_cbor_decref(float, &item);
}

void ctf_float4(void *ctx, float val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.float4)(ctx, val);
	if (!!(item = cbor_build_float4(val)))
		ctf_cbor_decref(float, &item);
}

void ctf_float8(void *ctx, double val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.float8)(ctx, val);
	if (!!(item = cbor_build_float8(val)))
		ctf_cbor_decref(float, &item);
}
