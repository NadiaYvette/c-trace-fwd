#include <cbor.h>

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
	(*cbor_empty_callbacks.boolean)(ctx, val);
}

void
ctf_indef_break(void *ctx)
{
	(*cbor_empty_callbacks.indef_break)(ctx);
}

void
ctf_tag(void *ctx, uint64_t val)
{
	(*cbor_empty_callbacks.tag)(ctx, val);
}
