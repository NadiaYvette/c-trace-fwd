#pragma once

#include <cbor.h>

void ctf_uint8(void *, uint8_t);		   /* cbor_int8_callback */
void ctf_uint16(void *, uint16_t);		   /* cbor_int16_callback */
void ctf_uint32(void *, uint32_t);		   /* cbor_int32_callback */
void ctf_uint64(void *, uint64_t);		   /* cbor_int64_callback */
void ctf_negint8(void *, uint8_t);		   /* cbor_int8_callback */
void ctf_negint16(void *, uint16_t);		   /* cbor_int16_callback */
void ctf_negint32(void *, uint32_t);		   /* cbor_int32_callback */
void ctf_negint64(void *, uint64_t);		   /* cbor_int64_callback */
void ctf_byte_string_start(void *);		   /* cbor_simple_callback */
void ctf_byte_string(void *, cbor_data, uint64_t); /* cbor_string_callback */
void ctf_string_start(void *);			   /* cbor_simple_callback */
void ctf_string(void *, cbor_data, uint64_t);	   /* cbor_string_callback */
void ctf_indef_array_start(void *);		   /* cbor_simple_callback */
void ctf_array_start(void *, uint64_t); /* cbor_collection_callback */
void ctf_indef_map_start(void *);	/* cbor_simple_callback */
void ctf_map_start(void *, uint64_t);	/* cbor_collection_callback */
void ctf_tag(void *, uint64_t);		/* cbor_int64_callback */
void ctf_float2(void *, float);		/* cbor_float_callback */
void ctf_float4(void *, float);		/* cbor_float_callback */
void ctf_float8(void *, double);	/* cbor_double_callback */
void ctf_undefined(void *);		/* cbor_simple_callback */
void ctf_null(void *);			/* cbor_simple_callback */
void ctf_boolean(void *, bool);		/* cbor_bool_callback */
void ctf_indef_break(void *);		/* cbor_simple_callback */
