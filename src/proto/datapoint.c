#include <cbor.h>
#include <glib.h>
#include <string.h>
#include <time.h>
#include "c_trace_fwd.h"
#include "sdu.h"
#include "datapoint.h"

void *
datapoint_encode_empty_resp(void)
{
	cbor_item_t *payload;
	size_t cbor_buf_sz = 0;
	struct sdu sdu = {
		.sdu_xmit = (uint32_t)time(NULL),
		.sdu_proto_un = { .sdu_proto_num = mpn_data_points, },
	};
	union sdu_ptr sdu_ptr;
	char *buf;
	unsigned char *cbor_buf;

	if (!(payload = build_empty_datapoint_resp()))
		return NULL;
	if (!(cbor_serialize_alloc(payload, &cbor_buf, &cbor_buf_sz)))
		goto out_free_payload;
	cbor_decref(&payload);
	if (!(buf = g_rc_box_alloc(cbor_buf_sz + 2*sizeof(uint32_t))))
		goto out_free_cbor_buf;
	sdu_ptr.sdu8 = (uint8_t *)buf;
	sdu.sdu_len = cbor_buf_sz;
	sdu.sdu_init_or_resp = true;
	if (sdu_encode(&sdu, sdu_ptr) != RETVAL_SUCCESS)
		goto out_free_buf;
	memcpy(&buf[2*sizeof(uint32_t)], cbor_buf, cbor_buf_sz);
	free(cbor_buf);
	return buf;
out_free_buf:
	g_rc_box_release(buf);
out_free_cbor_buf:
	free(cbor_buf);
out_free_payload:
	if (!!payload)
		cbor_decref(&payload);
	return NULL;
}

cbor_item_t *
build_empty_datapoint_resp(void)
{
	cbor_item_t *arr, *tag, *val;

	if (!(arr = cbor_new_definite_array(2)))
		return NULL;
	if (!(tag = cbor_build_uint8(datapoint_resp)))
		goto out_decref_arr;
	if (!cbor_array_set(arr, 0, tag))
		goto out_decref_tag;
	if (!(val = cbor_new_definite_array(0)))
		goto out_decref_tag;
	if (!cbor_array_set(arr, 1, val))
		goto out_decref_val;
	return arr;
out_decref_val:
	cbor_decref(&val);
out_decref_tag:
	cbor_decref(&tag);
out_decref_arr:
	cbor_decref(&arr);
	return NULL;
}
