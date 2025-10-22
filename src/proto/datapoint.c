#include <cbor.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "datapoint.h"
#include "mpn.h"
#include "sdu.h"
#include "tof.h"

char *
datapoint_hostname_reply(size_t *size)
{
	cbor_item_t *cbor_reply;
	size_t sz;
	unsigned char *buf;
	struct sdu sdu;
	union sdu_ptr sdu_ptr;

	if (!(cbor_reply = datapoint_hostname_reply_cbor()))
		return NULL;
	if (!(sz = cbor_serialized_size(cbor_reply)))
		goto out_free_cbor;
	sdu.sdu_len = sz;
	sdu.sdu_proto_un.sdu_proto_num = mpn_data_points;
	sdu.sdu_xmit = time(NULL);
	sdu.sdu_init_or_resp = true;
	sz += 2*sizeof(uint32_t);
	if (!(buf = g_rc_box_alloc(sz)))
		goto out_free_cbor;
	sdu_ptr.sdu8 = (uint8_t *)&buf[0];
	if (sdu_encode(&sdu, sdu_ptr) != RETVAL_SUCCESS)
		goto out_free_buf;
	if (!cbor_serialize(cbor_reply, &buf[2*sizeof(uint32_t)], sz))
		goto out_free_buf;
	ctf_cbor_decref(datapoint, &cbor_reply);
	*size = sz;
	return (char *)buf;
out_free_buf:
	g_rc_box_release(buf);
out_free_cbor:
	ctf_cbor_decref(datapoint, &cbor_reply);
	return NULL;
}

cbor_item_t *
datapoint_hostname_reply_cbor(void)
{
	char host_raw_str[] = "nyc-ipad-mini";
	char key_raw_str[] = "NodeInfo";
	unsigned char *reply_buf = NULL;
	size_t reply_buf_len = 0;
	cbor_item_t *top_ary, *mid_ary, *bot_ary, *key_str, *host_str, *host_bytestr, *tag_nr;

	if (!(top_ary = cbor_new_definite_array(2)))
		return NULL;
	if (!(mid_ary = cbor_new_definite_array(1)))
		goto out_free_top;
	if (!(bot_ary = cbor_new_definite_array(2)))
		goto out_free_mid;
	if (!(host_str = cbor_build_string(host_raw_str)))
		goto out_free_bot;
	if (!cbor_serialize_alloc(host_str, &reply_buf, &reply_buf_len))
		goto out_free_host;
	if (!(host_bytestr = cbor_build_bytestring(reply_buf, reply_buf_len)))
		goto out_free_reply_buf;
	if (!(key_str = cbor_build_string(key_raw_str)))
		goto out_free_host;
	if (!(tag_nr = cbor_new_int8()))
		goto out_free_key;
	cbor_set_uint8(tag_nr, 3);
	if (!cbor_array_set(top_ary, 0, tag_nr))
		goto out_free_tag;
	if (!cbor_array_set(top_ary, 1, mid_ary))
		goto out_free_tag;
	if (!cbor_array_set(mid_ary, 0, bot_ary))
		goto out_free_tag;
	if (!cbor_array_set(bot_ary, 0, key_str))
		goto out_free_tag;
	if (!cbor_array_set(bot_ary, 1, host_bytestr))
		goto out_free_tag;
	free(reply_buf);
	return top_ary;
out_free_tag:
	ctf_cbor_decref(datapoint, &tag_nr);
out_free_key:
	ctf_cbor_decref(datapoint, &key_str);
out_free_reply_buf:
	free(reply_buf);
out_free_host:
	ctf_cbor_decref(datapoint, &host_str);
out_free_bot:
	ctf_cbor_decref(datapoint, &bot_ary);
out_free_mid:
	ctf_cbor_decref(datapoint, &mid_ary);
out_free_top:
	ctf_cbor_decref(datapoint, &top_ary);
	return NULL;
}

void *
datapoint_encode_empty_resp(size_t *size)
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
	sdu.sdu_init_or_resp = CTF_INIT_OR_RESP;
	if (sdu_encode(&sdu, sdu_ptr) != RETVAL_SUCCESS)
		goto out_free_buf;
	*size = cbor_buf_sz + 2*sizeof(uint32_t);
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

bool
datapoint_examine(cbor_item_t *payload)
{
	cbor_item_t *entry, *bot, *key, *val, *val_decoded;
	struct cbor_load_result result;
	char *val_str = NULL;
	size_t val_str_len = 0;

	cbor_describe(payload, stdout);
	if (cbor_typeof(payload) != CBOR_TYPE_ARRAY)
		return false;
	if (cbor_array_size(payload) != 2)
		return false;
	if (!(entry = cbor_array_get(payload, 0)))
		return false;
	if (cbor_typeof(entry) != CBOR_TYPE_UINT)
		return false;
	if (cbor_int_get_width(entry) != CBOR_INT_8)
		return false;
	if (cbor_get_uint8(entry) != (int)mpn_data_points)
		return false;
	cbor_decref(&entry);
	if (!(entry = cbor_array_get(payload, 1)))
		return false;
	if (cbor_typeof(entry) != CBOR_TYPE_ARRAY)
		return false;
	if (cbor_array_size(entry) != 1)
		return false;
	if (!(bot = cbor_array_get(entry, 0)))
		return false;
	if (cbor_typeof(bot) != CBOR_TYPE_ARRAY)
		return false;
	if (cbor_array_size(bot) != 2)
		return false;
	if (!(key = cbor_array_get(bot, 0)))
		return false;
	if (cbor_typeof(key) != CBOR_TYPE_STRING)
		return false;
	if (!(val = cbor_array_get(bot, 1)))
		return false;
	if (cbor_typeof(val) != CBOR_TYPE_BYTESTRING)
		return false;
	/* decode & print key */
	/* decode val & cbor_load it & the describe it */
	if (!cbor_bytestrdup_array_get((const char **)&val_str, &val_str_len, bot, 1))
		goto out_free_val_str;
	if (!(val_decoded = cbor_load((unsigned char *)val_str, val_str_len, &result)))
		goto out_free_val_str;
	cbor_describe(val_decoded, stderr);
	fflush(stderr);
	(void)result;
	g_rc_box_release(val_str);
	return true;
out_free_val_str:
	g_rc_box_release(val_str);
	return false;
}
