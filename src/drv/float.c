#include <cbor.h>

void
ctf_float2(void *ctx, float val)
{
	(*cbor_empty_callbacks.float2)(ctx, val);
}

void
ctf_float4(void *ctx, float val)
{
	(*cbor_empty_callbacks.float4)(ctx, val);
}

void
ctf_float8(void *ctx, double val)
{
	(*cbor_empty_callbacks.float8)(ctx, val);
}
