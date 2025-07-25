#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv.h"
#include "ctf_util.h"

void ctf_uint8(void *ctx, uint8_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.uint8)(ctx, val);
	if (!!(item = cbor_build_uint8(val)))
		ctf_cbor_decref(int, &item);
}

void ctf_uint16(void *ctx, uint16_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.uint16)(ctx, val);
	if (!!(item = cbor_build_uint16(val)))
		ctf_cbor_decref(int, &item);
}

void ctf_uint32(void *ctx, uint32_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.uint32)(ctx, val);
	if (!!(item = cbor_build_uint32(val)))
		ctf_cbor_decref(int, &item);
}

void ctf_uint64(void *ctx, uint64_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.uint64)(ctx, val);
	if (!!(item = cbor_build_uint64(val)))
		ctf_cbor_decref(int, &item);
}

void ctf_negint8(void *ctx, uint8_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.negint8)(ctx, val);
	if (!!(item = cbor_build_negint8(val)))
		ctf_cbor_decref(int, &item);
}

void ctf_negint16(void *ctx, uint16_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.negint16)(ctx, val);
	if (!!(item = cbor_build_negint16(val)))
		ctf_cbor_decref(int, &item);
}

void ctf_negint32(void *ctx, uint32_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.negint32)(ctx, val);
	if (!!(item = cbor_build_negint32(val)))
		ctf_cbor_decref(int, &item);
}

void ctf_negint64(void *ctx, uint64_t val)
{
	cbor_item_t *item;

	(*cbor_empty_callbacks.negint64)(ctx, val);
	if (!!(item = cbor_build_negint64(val)))
		ctf_cbor_decref(int, &item);
}
