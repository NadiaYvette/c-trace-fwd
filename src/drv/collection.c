#include <cbor.h>

void
ctf_indef_array_start(void *ctx)
{
	(*cbor_empty_callbacks.indef_array_start)(ctx);
}

void
ctf_array_start(void *ctx, uint16_t len)
{
	(*cbor_empty_callbacks.array_start)(ctx, len);
}

void
ctf_indef_map_start(void *ctx)
{
	(*cbor_empty_callbacks.indef_map_start)(ctx);
}

void
ctf_map_start(void *ctx, uint16_t len)
{
	(*cbor_empty_callbacks.array_start)(ctx, len);
}
