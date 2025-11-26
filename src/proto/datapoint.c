#include <cbor.h>
#include <glib.h>
#include <json_object.h>
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
	cbor_describe(cbor_reply, stderr);
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
	char host_raw_str[] = "mainnetsingle";
	char key_raw_str[] = "NodeInfo";
	unsigned char *reply_buf = NULL;
	size_t k, reply_buf_len = 0;
	cbor_item_t *top_ary, *upp_ary, *mid_ary, *bot_ary,
		    *key_str, *host_str, *host_bytestr, *tag_nr;
	struct json_object *ni_json_obj, *ni_name, *ni_proto,
			   *ni_version, *ni_commit, *ni_start_time,
			   *ni_system_start_time;
	const char *ni_json_str;

	/* NodeInfo values taken from log capture */
	if (!(top_ary = cbor_new_definite_array(2)))
		return NULL;
	if (!(upp_ary = cbor_new_indefinite_array()))
		goto out_free_top;
	if (!(mid_ary = cbor_new_definite_array(2)))
		goto out_free_upp;
	if (!(bot_ary = cbor_new_definite_array(1)))
		goto out_free_mid;
	if (!(ni_name = json_object_new_string(host_raw_str)))
		goto out_free_bot;
	if (!(ni_proto = json_object_new_string("Byron; Shelley")))
		goto out_free_ni_name;
	if (!(ni_version = json_object_new_string("10.5.0")))
		goto out_free_ni_proto;
	if (!(ni_commit = json_object_new_string("64ed6659885a88d3aad4fd22e01d7fa8d1507887")))
		goto out_free_ni_version;
	if (!(ni_start_time = json_object_new_string("2025-10-22T08:58:43.565577801Z")))
		goto out_free_ni_commit;
	if (!(ni_system_start_time = json_object_new_string("2017-09-23T21:44:51Z")))
		goto out_free_ni_start_time;
	if (!(ni_json_obj = json_object_new_object()))
		goto out_free_ni_system_start_time;
	if (!!json_object_object_add(ni_json_obj, "niName", ni_name))
		goto out_free_json_obj;
	if (!!json_object_object_add(ni_json_obj, "niProtocol", ni_proto))
		goto out_free_json_obj;
	if (!!json_object_object_add(ni_json_obj, "niVersion", ni_version))
		goto out_free_json_obj;
	if (!!json_object_object_add(ni_json_obj, "niCommit", ni_commit))
		goto out_free_json_obj;
	if (!!json_object_object_add(ni_json_obj, "niStartTime", ni_start_time))
		goto out_free_json_obj;
	if (!!json_object_object_add(ni_json_obj, "niSystemStartTime", ni_system_start_time))
		goto out_free_json_obj;
	if (!(ni_json_str = json_object_to_json_string_ext(ni_json_obj, JSON_C_TO_STRING_PLAIN)))
		goto out_free_json_obj;
	ctf_msg(ctf_debug, datapoint, "%s\n", ni_json_str);
	if (!(host_str = cbor_build_bytestring((cbor_data)ni_json_str, strlen(ni_json_str))))
		goto out_free_json_str;
	if (!(host_bytestr = cbor_new_indefinite_bytestring()))
		goto out_free_reply_buf;
	if (!(key_str = cbor_build_string(key_raw_str)))
		goto out_free_host_bytestr;
	if (!(tag_nr = cbor_new_int8()))
		goto out_free_key;
	cbor_set_uint8(tag_nr, datapoint_resp);
	if (!cbor_array_set(top_ary, 0, tag_nr))
		goto out_free_tag;
	if (!cbor_array_set(top_ary, 1, upp_ary))
		goto out_free_tag;
	if (!cbor_array_push(upp_ary, mid_ary))
		goto out_free_tag;
	if (!cbor_array_set(mid_ary, 0, key_str))
		goto out_free_tag;
	if (!cbor_array_set(mid_ary, 1, bot_ary))
		goto out_free_tag;
	if (!cbor_array_set(bot_ary, 0, host_bytestr))
		goto out_free_tag;
	if (!cbor_bytestring_add_chunk(host_bytestr, host_str))
		goto out_free_tag;
	if (!cbor_serialize_alloc(top_ary, &reply_buf, &reply_buf_len))
		goto out_free_tag;
	(void)!fprintf(stderr, "NodeInfo %s\n", ni_json_str);
	(void)!fputc('\n', stderr);
	for (k = 0; k < reply_buf_len; ++k) {
		(void)!fprintf(stderr, "%02x", (unsigned)reply_buf[k]);
		if (k + 1 < reply_buf_len)
			(void)!fputc((int)' ', stderr);
	}
	(void)!fputc('\n', stderr);
	cbor_decref(&tag_nr);
	cbor_decref(&upp_ary);
	cbor_decref(&mid_ary);
	cbor_decref(&bot_ary);
	cbor_decref(&key_str);
	cbor_decref(&host_bytestr);
	cbor_decref(&host_str);
	json_object_put(ni_json_obj);
	(void)!ni_json_str;
	free(reply_buf);
	return top_ary;
out_free_tag:
	ctf_cbor_decref(datapoint, &tag_nr);
out_free_key:
	ctf_cbor_decref(datapoint, &key_str);
out_free_host_bytestr:
	ctf_cbor_decref(datapoint, &host_bytestr);
out_free_reply_buf:
	free(reply_buf);
out_free_host:
	ctf_cbor_decref(datapoint, &host_str);
out_free_json_str:
	(void)!ni_json_str;
out_free_json_obj:
	json_object_put(ni_json_obj);
out_free_ni_system_start_time:
	(void)!json_object_put(ni_system_start_time);
out_free_ni_start_time:
	(void)!json_object_put(ni_start_time);
out_free_ni_commit:
	(void)!json_object_put(ni_commit);
out_free_ni_version:
	(void)!json_object_put(ni_version);
out_free_ni_proto:
	(void)!json_object_put(ni_proto);
out_free_ni_name:
	(void)!json_object_put(ni_name);
out_free_bot:
	ctf_cbor_decref(datapoint, &bot_ary);
out_free_mid:
	ctf_cbor_decref(datapoint, &mid_ary);
out_free_upp:
	ctf_cbor_decref(datapoint, &upp_ary);
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
	cbor_decref(&tag);
	if (!(val = cbor_new_definite_array(0)))
		goto out_decref_arr;
	if (!cbor_array_set(arr, 1, val))
		goto out_decref_val;
	cbor_decref(&val);
	return arr;
out_decref_val:
	cbor_decref(&val);
	goto out_decref_arr;
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
	if (cbor_get_uint8(entry) != (int)datapoint_resp)
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
	if (cbor_isa_array(val) && cbor_array_size(val) == 1) {
		if (!cbor_bytestrdup_array_get((const char **)&val_str, &val_str_len, val, 0)) {
			cbor_decref(&val);
			goto out_free_val_str;
		}
	} else if (cbor_isa_bytestring(val)) {
		if (!cbor_bytestrdup_array_get((const char **)&val_str, &val_str_len, bot, 1)) {
			cbor_decref(&val);
			goto out_free_val_str;
		}
	} else {
		cbor_decref(&val);
		return false;
	}
	cbor_decref(&val);
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
