#include <cbor.h>

void
ctf_uint8(void *ctx, uint8_t val)
{
	(*cbor_empty_callbacks.uint8)(ctx, val);
}

void
ctf_uint16(void *ctx, uint16_t val)
{
	(*cbor_empty_callbacks.uint16)(ctx, val);
}

void
ctf_uint32(void *ctx, uint32_t val)
{
	(*cbor_empty_callbacks.uint32)(ctx, val);
}

void
ctf_uint64(void *ctx, uint64_t val)
{
	(*cbor_empty_callbacks.uint64)(ctx, val);
}

void
ctf_negint8(void *ctx, uint8_t val)
{
	(*cbor_empty_callbacks.negint8)(ctx, val);
}

void
ctf_negint16(void *ctx, uint16_t val)
{
	(*cbor_empty_callbacks.negint16)(ctx, val);
}

void
ctf_negint32(void *ctx, uint32_t val)
{
	(*cbor_empty_callbacks.negint32)(ctx, val);
}

void
ctf_negint64(void *ctx, uint64_t val)
{
	(*cbor_empty_callbacks.negint64)(ctx, val);
}
