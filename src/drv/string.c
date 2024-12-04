#include <cbor.h>

void
ctf_string_start(void *ctx)
{
	(*cbor_empty_callbacks.string_start)(ctx);
}

void
ctf_string(void *ctx, cbor_data buf, uint64_t len)
{
	(*cbor_empty_callbacks.string)(ctx, buf, len);
}

void
ctf_byte_string_start(void *ctx)
{
	(*cbor_empty_callbacks.byte_string_start)(ctx);
}

void
ctf_byte_string(void *ctx, cbor_data buf, uint64_t len)
{
	(*cbor_empty_callbacks.byte_string)(ctx, buf, len);
}
