#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "handshake.h"
#include "tof.h"

const char *
tof_msg_type_string(enum tof_msg_type type)
{
	static const char *tof_msg_type_strings[] = {
		[0]           = NULL,
		[tof_request] = "tof_request",
		[tof_done]    = "tof_done",
		[tof_reply]   = "tof_reply",
	};

	if (TOF_MSG_TYPE_VALID(type))
		return tof_msg_type_strings[type];
	else
		return NULL;
}

bool
tof_valid_msg_type(const enum tof_msg_type type)
{
	if (type >= TOF_MSG_TYPE_MIN && type <= TOF_MSG_TYPE_MAX)
		return true;
	switch (type) {
	case tof_request /* == 1 */:
	case tof_done    /* == 2 */:
	case tof_reply   /* == 3 */:
		return true;
	default:
		if (type == 0)
			ctf_msg(ctf_alert, tof,
					"invalid tof_msg_type 0 seen!\n");
		else
			ctf_msg(ctf_alert, tof,
					"unrecognized tof_msg_type %d "
					"seen!\n", type);
		return false;
	}
}

/* TODO: error handling */

static bool
to_uint_array_get(const cbor_item_t *array, unsigned k, uintmax_t *val)
{
	bool ret;
	cbor_item_t *item = NULL;

	if (!(item = cbor_array_get(array, k))) {
		ctf_msg(ctf_alert, tof, "cbor_array_get() failed\n");
		return false;
	}
	if (cbor_is_null(item)) {
		ctf_msg(ctf_alert, tof, "NULL got from array\n");
		cbor_describe(item, stderr);
		ret = false;
		goto out_uint_free;
	}
	switch (cbor_typeof(item)) {
	case CBOR_TYPE_TAG:
		cbor_item_t *tagged;

		if (!(tagged = cbor_tag_item(item))) {
			ctf_msg(ctf_alert, tof, "cbor_tag_item() failed!\n");
			ret = false;
			ctf_cbor_decref(tof, &tagged);
			goto out_uint_free;
		}
		ret = to_uint_array_get(tagged, 1, val);
		break;
	case CBOR_TYPE_UINT:
		if (!(ret = cbor_get_uint(item, val)))
			ctf_msg(ctf_alert, tof, "cbor_get_uint() failed!\n");
		break;
	case CBOR_TYPE_ARRAY:
		cbor_item_t *subarray = item;

		if (!(item = cbor_array_get(subarray, 0))) {
			ret = false;
			ctf_msg(ctf_alert, tof, "cbor_array_get() failed\n");
			cbor_describe(subarray, stderr);
			ctf_cbor_decref(tof, &subarray);
			goto out_uint_free;
		}
		ret = cbor_get_uint(item, val);
		if (!ret) {
			ctf_msg(ctf_alert, tof, "cbor_get_uint() failed\n");
			cbor_describe(subarray, stderr);
		}
		ctf_cbor_decref(tof, &subarray);
		break;
	case CBOR_TYPE_MAP:
		cbor_item_t *map = item;
		struct cbor_pair *pairs;
		size_t size;
		unsigned k;

		if (!(pairs = cbor_map_handle(map))) {
			ctf_msg(ctf_alert, tof, "map handle NULL\n");
			ret = false;
			cbor_describe(map, stderr);
			goto out_uint_free;
		}
		size = cbor_map_size(map);
		for (k = 0; k < size; ++k) {
			if (!cbor_isa_uint(pairs[k].key))
				continue;
			if (cbor_int_get_width(pairs[k].key) != CBOR_INT_8)
				continue;
			if (cbor_get_uint8(pairs[k].key) != 1U)
				continue;
			if (!!(ret = cbor_get_uint(pairs[k].value, val))) {
				ctf_cbor_decref(tof, &map);
				goto out_uint_free;
			}
		}
		ret = false;
		ctf_msg(ctf_alert, tof, "no map entry for 1 found\n");
		cbor_describe(map, stderr);
		ctf_cbor_decref(tof, &map);
		break;
	default:
		ctf_msg(ctf_alert, tof, "unrecognised item type\n");
		cbor_describe(item, stderr);
		ret = false;
	}
out_uint_free:
	if (!!item)
		ctf_cbor_decref(tof, &item);
	else
		ctf_msg(ctf_alert, tof, "item NULL at out_uint_free\n");
	return ret;
}

bool
cbor_strdup_array_get(const char **string, const cbor_item_t *array, unsigned k)
{
	bool retval;
	cbor_item_t *item;
	char *new_string = NULL;

	if (!(item = cbor_array_get(array, k))) {
		ctf_msg(ctf_alert, tof, "cbor_array_get() failed\n");
		return false;
	}
	if (cbor_is_null(item)) {
		ctf_msg(ctf_alert, tof, "null item\n");
		*string = NULL;
		return false;
	}
	if (!cbor_isa_string(item)) {
		ctf_msg(ctf_alert, tof, "item not a string\n");
		cbor_describe((cbor_item_t *)array, stderr);
		retval = false;
		goto out_string_free;
	}
	if (cbor_string_is_definite(item)) {
		size_t new_string_len = cbor_string_length(item);

		if (!(new_string = (char *)cbor_string_handle(item))) {
			ctf_msg(ctf_alert, tof, "string handle NULL\n");
			retval = false;
			goto out_string_free;
		}
		if (!(*string = g_rc_box_dup(new_string_len, new_string))) {
			ctf_msg(ctf_alert, tof, "strdup() failed\n");
			retval = false;
			goto out_string_free;
		}
		retval = true;
	} else if (cbor_string_is_indefinite(item)) {
		cbor_item_t **chunks;
		size_t k, nr_chunks;
		char *cur;

		if (!(chunks = cbor_string_chunks_handle(item))) {
			ctf_msg(ctf_alert, tof,
				"cbor_string_chunks_handle() failed\n");
			retval = false;
			goto out_string_free;
		}
		nr_chunks = cbor_string_chunk_count(item);
		if (!(new_string = g_rc_box_alloc0(cbor_string_length(item) * sizeof(char)))) {
			retval = false;
			goto out_string_free;
		}
		for (k = 0, cur = new_string; k < nr_chunks; ++k)
			cur = stpcpy(cur, (const char *)cbor_string_handle(chunks[k]));
		*string = new_string;
		retval = true;
	} else
		retval = false;
out_string_free:
	ctf_cbor_decref(tof, &item);
	return retval;
}

bool
cbor_bytestrdup_array_get(const char **string, size_t *len, const cbor_item_t *array, unsigned k)
{
	bool retval;
	cbor_item_t *item;
	char *new_string = NULL;

	if (!(item = cbor_array_get(array, k))) {
		ctf_msg(ctf_alert, tof, "cbor_array_get() failed\n");
		return false;
	}
	if (cbor_is_null(item)) {
		ctf_msg(ctf_alert, tof, "null item\n");
		*string = NULL;
		return false;
	}
	if (!cbor_isa_bytestring(item)) {
		ctf_msg(ctf_alert, tof, "item not a string\n");
		cbor_describe((cbor_item_t *)array, stderr);
		retval = false;
		goto out_string_free;
	}
	if (cbor_bytestring_is_definite(item)) {
		size_t new_string_len = cbor_bytestring_length(item);

		if (!(new_string = (char *)cbor_bytestring_handle(item))) {
			ctf_msg(ctf_alert, tof, "string handle NULL\n");
			retval = false;
			goto out_string_free;
		}
		if (!(*string = g_rc_box_dup(new_string_len, new_string))) {
			ctf_msg(ctf_alert, tof, "strdup() failed\n");
			retval = false;
			goto out_string_free;
		}
		*len = new_string_len;
		retval = true;
	} else if (cbor_bytestring_is_indefinite(item)) {
		cbor_item_t **chunks;
		size_t k, nr_chunks, new_string_len;
		char *cur;

		if (!(chunks = cbor_bytestring_chunks_handle(item))) {
			ctf_msg(ctf_alert, tof,
				"cbor_bytestring_chunks_handle() failed\n");
			retval = false;
			goto out_string_free;
		}
		nr_chunks = cbor_bytestring_chunk_count(item);
		for (k = 0, new_string_len = 0; k < nr_chunks; ++k)
			new_string_len += cbor_bytestring_length(chunks[k]);
		if (!(new_string = g_rc_box_alloc0(new_string_len))) {
			retval = false;
			goto out_string_free;
		}
		for (k = 0, cur = new_string; k < nr_chunks; ++k)
			cur = mempcpy(cur, (const char *)cbor_bytestring_handle(chunks[k]), cbor_bytestring_length(chunks[k]));
		*string = new_string;
		retval = true;
	} else
		retval = false;
out_string_free:
	ctf_cbor_decref(tof, &item);
	return retval;
}

struct trace_object *
trace_object_decode(const cbor_item_t *array)
{
	size_t k, n;
	uintmax_t val;
	struct trace_object *to;
	cbor_item_t *subarray;

	if (!(to = g_rc_box_new0(struct trace_object))) {
		ctf_msg(ctf_alert, tof, "g_rc_box_new0() failed\n");
		return NULL;
	}

	if (!cbor_isa_array(array)) {
		ctf_msg(ctf_alert, tof, "not of array type\n");
		goto out_free_to;
	}
	if ((n = cbor_array_size(array)) != 9)
		ctf_msg(ctf_alert, tof,
				"unexpected trace_object "
				"array length %d\n", n);
	if (!(subarray = cbor_array_get(array, 1))) {
		ctf_msg(ctf_alert, tof, "subarray get failed\n");
		goto out_free_to;
	}
	if (cbor_is_null(subarray)) {
		ctf_msg(ctf_alert, tof, "null subarray\n");
		ctf_cbor_decref(tof, &subarray);
		goto out_free_to;
	}
	if (!cbor_isa_array(subarray)) {
		ctf_msg(ctf_alert, tof, "subarray not an array\n");
		ctf_cbor_decref(tof, &subarray);
		goto out_free_to;
	}
	if (cbor_is_null(subarray) || !cbor_isa_array(subarray) || cbor_array_size(subarray) < 1)
		to->to_human = NULL;
	else if (!cbor_strdup_array_get(&to->to_human, subarray, 0)) {
		ctf_msg(ctf_alert, tof, "human lacking\n");
		/* field optional */
		/* goto out_free_to; */
	}

	if (!cbor_strdup_array_get(&to->to_machine, array, 2)) {
		ctf_msg(ctf_alert, tof, "machine lacking\n");
		/* field optional */
		/* goto out_free_to; */
	}

	if (!(subarray = cbor_array_get(array, 3))) {
		ctf_msg(ctf_alert, tof, "namespace lacking\n");
		goto out_free_machine;
	}
	if (!cbor_isa_array(subarray)) {
		ctf_msg(ctf_alert, tof, "namespace not an array\n");
		ctf_cbor_decref(tof, &subarray);
		goto out_free_machine;
	}
	/* tags don't get used in this case */
	to->to_namespace_nr = cbor_array_size(subarray);
	if (!(to->to_namespace = g_rc_box_alloc0(to->to_namespace_nr * sizeof(char *)))) {
		ctf_msg(ctf_alert, tof,
				"namespace g_rc_box_alloc0() failed\n");
		ctf_cbor_decref(tof, &subarray);
		goto out_free_machine;
	}
	for (k = 0; k < to->to_namespace_nr; ++k) {
		if (cbor_strdup_array_get(&to->to_namespace[k], subarray, k))
			continue;
		ctf_msg(ctf_alert, tof, "namespace strdup() failed\n");
		ctf_cbor_decref(tof, &subarray);
		goto out_free_namespace_entries;
	}

	if (!to_uint_array_get(array, 4, &val)) {
		ctf_msg(ctf_alert, tof, "severity failed\n");
		goto out_free_namespace_entries;
	}
	to->to_severity = (enum severity_s)val;

	if (!to_uint_array_get(array, 5, &val)) {
		ctf_msg(ctf_alert, tof, "detail failed\n");
		goto out_free_namespace_entries;
	}
	to->to_details = (enum detail_level)val;

	if (!to_uint_array_get(array, 6, &val)) {
		ctf_msg(ctf_alert, tof, "timestamp failed\n");
		if (0)
			cbor_describe((cbor_item_t *)array, stderr);
		goto out_free_namespace_entries;
	}
	to->to_timestamp = (time_t)val;

	if (!cbor_strdup_array_get(&to->to_hostname, array, 7)) {
		ctf_msg(ctf_alert, tof, "hostname failed\n");
		goto out_free_namespace_entries;
	}
	if (!cbor_strdup_array_get(&to->to_thread_id, array, 8)) {
		ctf_msg(ctf_alert, tof, "thread_id failed\n");
		goto out_free_hostname;
	}
	return to;
out_free_hostname:
	g_rc_box_release((void *)to->to_hostname);
out_free_namespace_entries:
	for (k = 0; k < to->to_namespace_nr; ++k)
		g_rc_box_release((void *)to->to_namespace[k]);
	g_rc_box_release(to->to_namespace);
out_free_machine:
	g_rc_box_release((void *)to->to_machine);
/* out_free_human: */
	g_rc_box_release((void *)to->to_human);
out_free_to:
	g_rc_box_release(to);
	if (0)
		cbor_describe((cbor_item_t *)array, stderr);
	return NULL;
}

cbor_item_t *
trace_object_encode(const struct trace_object *trace_object)
{
	int k;
	cbor_item_t *array, *human_array;
	cbor_item_t *human, *machine, *namespace, *severity,
		    *details, *timestamp, *hostname, *thread_id;

	if (!(array = cbor_new_definite_array(8))) {
		ctf_msg(ctf_alert, tof, "cbor_new_definite_array failed\n");
		return NULL;
	}
	if (!trace_object->to_human) {
		ctf_msg(ctf_debug, tof, "NULL ->to_human\n");
		human = cbor_new_null();
	} else
		human = cbor_build_string(trace_object->to_human);
	if (!human) {
		ctf_msg(ctf_alert, tof, "human cbor_build_string failed\n");
		goto out_free_array;
	}
	if (!(human_array = cbor_new_definite_array(1))) {
		ctf_msg(ctf_alert, tof, "human_array failed\n");
		ctf_cbor_decref(tof, &human);
		goto out_free_array;
	}
	if (!cbor_array_set(human_array, 0, human)) {
		ctf_msg(ctf_alert, tof, "human_array set elt 0 failed\n");
		ctf_cbor_decref(tof, &human);
		goto out_free_human_array;
	}
	if (!cbor_array_set(array, 0, human_array)) {
		ctf_msg(ctf_alert, tof, "human_array set ary elt failed\n");
		goto out_free_human_array;
	}
	if (!(machine = cbor_build_string(trace_object->to_machine))) {
		ctf_msg(ctf_alert, tof, "machine cbor_build_string failed\n");
		goto out_free_array;
	}
	if (!cbor_array_set(array, 1, machine)) {
		ctf_msg(ctf_alert, tof, "machine set ary elt failed\n");
		goto out_free_machine;
	}
	namespace = cbor_new_definite_array(trace_object->to_namespace_nr);
	if (!namespace) {
		ctf_msg(ctf_alert, tof, "namespace cbor_new_definite_array failed\n");
		goto out_free_array;
	}
	for (k = 0; k < trace_object->to_namespace_nr; ++k) {
		cbor_item_t *item;

		if (!(item = cbor_build_string(trace_object->to_namespace[k]))) {
			ctf_msg(ctf_alert, tof, "namespace cbor_build_string for elt %d failed\n", k);
			goto out_free_namespace;
		}
		if (!cbor_array_set(namespace, k, item)) {
			ctf_msg(ctf_alert, tof, "namespace set elt %d failed\n", k);
			ctf_cbor_decref(tof, &item);
			goto out_free_namespace;
		}
	}
	if (!cbor_array_set(array, 2, namespace)) {
		ctf_msg(ctf_alert, tof, "namespace set ary elt failed\n");
		goto out_free_namespace;
	}
	if (!(severity = cbor_new_int32())) {
		ctf_msg(ctf_alert, tof, "severity cbor_new_int32 failed\n");
		goto out_free_array;
	}
	cbor_set_uint32(severity, trace_object->to_severity);
	if (!cbor_array_set(array, 3, severity)) {
		ctf_msg(ctf_alert, tof, "severity set ary elt failed\n");
		goto out_free_severity;
	}
	if (!(details = cbor_new_int32())) {
		ctf_msg(ctf_alert, tof, "details cbor_new_int32 failed\n");
		goto out_free_array;
	}
	cbor_set_uint32(details, trace_object->to_details);
	if (!cbor_array_set(array, 4, details)) {
		ctf_msg(ctf_alert, tof, "details set ary elt failed\n");
		goto out_free_details;
	}
	if (!(timestamp = cbor_build_uint64(trace_object->to_timestamp))) {
		ctf_msg(ctf_alert, tof, "timestamp cbor_build_uint64 failed\n");
		goto out_free_array;
	}
	if (!cbor_array_set(array, 5, timestamp)) {
		ctf_msg(ctf_alert, tof, "timestamp set ary elt failed\n");
		goto out_free_timestamp;
	}
	if (!(hostname = cbor_build_string(trace_object->to_hostname))) {
		ctf_msg(ctf_alert, tof, "hostname cbor_build_string failed\n");
		goto out_free_array;
	}
	if (!cbor_array_set(array, 6, hostname)) {
		ctf_msg(ctf_alert, tof, "hostname set ary elt failed\n");
		goto out_free_hostname;
	}
	if (!(thread_id = cbor_build_string(trace_object->to_thread_id))) {
		ctf_msg(ctf_alert, tof, "thread_id cbor_build_string failed\n");
		goto out_free_array;
	}
	if (!cbor_array_set(array, 7, thread_id)) {
		ctf_msg(ctf_alert, tof, "thread_id set ary elt failed\n");
		goto out_free_thread_id;
	}
	return array;
	/*
	 * array holds the reference counts for all of the array entries.
	 * Falling through would be a double refcount release. The
	 * individual components' labels are for failures to link into
	 * the larger structures holding references to them.
	 */
out_free_human_array:
	ctf_cbor_decref(tof, &human_array);
	goto out_free_array;
out_free_machine:
	ctf_cbor_decref(tof, &machine);
	goto out_free_array;
out_free_namespace:
	ctf_cbor_decref(tof, &namespace);
	goto out_free_array;
out_free_severity:
	ctf_cbor_decref(tof, &severity);
	goto out_free_array;
out_free_details:
	ctf_cbor_decref(tof, &details);
	goto out_free_array;
out_free_timestamp:
	ctf_cbor_decref(tof, &timestamp);
	goto out_free_array;
out_free_hostname:
	ctf_cbor_decref(tof, &hostname);
	goto out_free_array;
out_free_thread_id:
	ctf_cbor_decref(tof, &thread_id);
	goto out_free_array;
out_free_array:
	ctf_cbor_decref(tof, &array);
	return NULL;
}

cbor_item_t *
tof_encode(const struct tof_msg *msg)
{
	cbor_item_t *msg_type, *msg_array = NULL;
	cbor_item_t *reply_array = NULL;

	switch (msg->tof_msg_type) {
	case tof_done:
		if (!(msg_array = cbor_new_definite_array(1))) {
			ctf_msg(ctf_alert, tof,
					"msg_array allocation failed!\n");
			return NULL;
		}
		if (!(msg_type = cbor_build_uint32(tof_done)))
			goto out_free_msg_array;
		if (!cbor_array_set(msg_array, 0, msg_type))
			goto out_free_msg_type;
		break;

	case tof_request:
		const struct tof_request *request = &msg->tof_msg_body.request;
		cbor_item_t *tof_nr_obj, *tof_blocking;

		if (!(msg_array = cbor_new_definite_array(3))) {
			ctf_msg(ctf_alert, tof,
					"msg_array allocation failed!\n");
			return NULL;
		}
		if (!(msg_type = cbor_build_uint32(tof_request)))
			goto out_free_msg_array;
		if (!cbor_array_set(msg_array, 0, msg_type))
			goto out_free_msg_type;
		if (!(tof_blocking = cbor_build_bool(request->tof_blocking)))
			goto out_free_msg_type;
		if (!cbor_array_set(msg_array, 1, tof_blocking))
			goto out_free_tof_blocking;
		if (!(tof_nr_obj = cbor_build_uint16(request->tof_nr_obj)))
			goto out_free_msg_array;
		if (!cbor_array_set(msg_array, 2, tof_nr_obj))
			goto out_free_tof_nr_obj;
		break;
	out_free_tof_nr_obj:
		ctf_cbor_decref(tof, &tof_nr_obj);
		goto out_free_msg_array;
	out_free_tof_blocking:
		ctf_cbor_decref(tof, &tof_blocking);
		goto out_free_msg_array;

	case tof_reply:
		const struct tof_reply *reply = &msg->tof_msg_body.reply;
		unsigned k;

		if (!(msg_array = cbor_new_definite_array(2))) {
			ctf_msg(ctf_alert, tof,
					"msg_array allocation failed!\n");
			return NULL;
		}
		if (!(msg_type = cbor_build_uint32(tof_reply)))
			goto out_free_msg_array;
		if (!cbor_array_set(msg_array, 0, msg_type))
			goto out_free_msg_type;
		reply_array = cbor_new_definite_array(reply->tof_nr_replies);
		if (!reply_array)
			goto out_free_msg_array;
		for (k = 0; k < reply->tof_nr_replies; ++k) {
			cbor_item_t *reply_array_entry
				= trace_object_encode(reply->tof_replies[k]);

			if (!reply_array_entry) {
				ctf_msg(ctf_alert, tof,
					"trace_object_encode()"
					     "failed on reply->"
					     "tof_replies[%u]\n", k);
				goto out_free_reply_array;
				break;
			}
			if (cbor_array_set(reply_array, k, reply_array_entry))
				continue;
			ctf_cbor_decref(tof, &reply_array_entry);
			goto out_free_reply_array;
		}
		if (!cbor_array_set(msg_array, 1, reply_array))
			goto out_free_reply_array;
		break;
	}
	return msg_array;
	/*
	 * msg_array holds the reference counts for all of the array entries.
	 * Falling through would be a double refcount release. The
	 * individual components' labels are for failures to link into
	 * the larger structures holding references to them.
	 */
out_free_reply_array:
	ctf_cbor_decref(tof, &reply_array);
	goto out_free_msg_array;
out_free_msg_type:
	ctf_cbor_decref(tof, &msg_type);
	goto out_free_msg_array;
out_free_msg_array:
	ctf_cbor_decref(tof, &msg_array);
	return NULL;
}

static bool
tof_nr_obj_decode_uint(const cbor_item_t *nr_obj_item, uint16_t *val)
{
	if (!nr_obj_item || !val)
		return false;
	switch (cbor_int_get_width(nr_obj_item)) {
	case CBOR_INT_8:
		*val = cbor_get_uint8(nr_obj_item);
		return true;
	case CBOR_INT_16:
		*val = cbor_get_uint16(nr_obj_item);
		return true;
	case CBOR_INT_32:
		if (cbor_get_uint32(nr_obj_item) <= UINT16_MAX) {
			*val = cbor_get_uint32(nr_obj_item);
			return true;
		}
		ctf_msg(ctf_alert, tof, "nr_obj too large (32-bit)!\n");
		return false;
	case CBOR_INT_64:
		if (cbor_get_uint64(nr_obj_item) <= UINT16_MAX) {
			*val = cbor_get_uint64(nr_obj_item);
			return true;
		}
		ctf_msg(ctf_alert, tof, "nr_obj too large (64-bit)!\n");
		return false;
	default:
		ctf_msg(ctf_alert, tof,
				"unrecognized nr_obj integer width\n");
		return false;
	}
}

static bool
tof_nr_obj_decode_array(const cbor_item_t *nr_obj_item, uint16_t *val)
{
	cbor_item_t *lower, *upper;
	uint16_t lower_val;
	bool ret = true;

	if (!nr_obj_item || !val)
		return false;
	if (cbor_array_size(nr_obj_item) != 2) {
		ctf_msg(ctf_alert, tof, "nr_obj array size = %zd != 2!\n",
				cbor_array_size(nr_obj_item));
		return false;
	}
	if (!(lower = cbor_array_get(nr_obj_item, 0))) {
		ctf_msg(ctf_alert, tof,
				"cbor_array_get(nr_obj_item, 0) failed!\n");
		return false;
	}
	if (!(upper = cbor_array_get(nr_obj_item, 1))) {
		ctf_msg(ctf_alert, tof,
				"cbor_array_get(nr_obj_item, 1) failed!\n");
		ctf_cbor_decref(tof, &lower);
		return false;
	}
	ret = ret && tof_nr_obj_decode_uint(lower, &lower_val);
	ret = ret && tof_nr_obj_decode_uint(upper, val);
	ret = ret && !!(lower_val == 0);
	ctf_cbor_decref(tof, &lower);
	ctf_cbor_decref(tof, &upper);
	return ret;
}

static bool
tof_nr_obj_decode(const cbor_item_t *nr_obj_item, uint16_t *val)
{
	if (!nr_obj_item)
		return false;
	switch (cbor_typeof(nr_obj_item)) {
	case CBOR_TYPE_UINT:
		return tof_nr_obj_decode_uint(nr_obj_item, val);
		break;
	case CBOR_TYPE_ARRAY:
		return tof_nr_obj_decode_array(nr_obj_item, val);
		break;
	case CBOR_TYPE_NEGINT:
		ctf_msg(ctf_alert, tof, "nr_obj of negint type!\n");
		return false;
	case CBOR_TYPE_BYTESTRING:
		ctf_msg(ctf_alert, tof, "nr_obj of bytestring type!\n");
		return false;
	case CBOR_TYPE_STRING:
		ctf_msg(ctf_alert, tof, "nr_obj of string type!\n");
		return false;
	case CBOR_TYPE_MAP:
		ctf_msg(ctf_alert, tof, "nr_obj of map type!\n");
		return false;
	case CBOR_TYPE_TAG:
		ctf_msg(ctf_alert, tof, "nr_obj of tag type!\n");
		return false;
	case CBOR_TYPE_FLOAT_CTRL:
		ctf_msg(ctf_alert, tof, "nr_obj of float_ctrl type!\n");
		return false;
	default:
		ctf_msg(ctf_alert, tof, "nr_obj of unrecognized type!\n");
		return false;
	}
}

struct tof_msg *
tof_decode(const cbor_item_t *msg)
{
	struct tof_msg *tof;
	cbor_item_t *item, *reply_array = NULL;

	ctf_msg(ctf_debug, tof, "entered tof_decode()\n");
	if (!msg) {
		ctf_msg(ctf_alert, tof, "NULL msg!\n");
		return NULL;
	}
	if (!(tof = g_rc_box_new0(struct tof_msg))) {
		ctf_msg(ctf_alert, tof, "tof allocation failed!\n");
		return NULL;
	}
	if (!cbor_isa_array(msg)) {
		ctf_msg(ctf_alert, tof, "cbor msg not an array!\n");
		goto exit_free_tof;
	}
	if (cbor_array_size(msg) < 1) {
		ctf_msg(ctf_alert, tof,
				"cbor msg is an empty array, no type!\n");
		goto exit_free_tof;
	}
	if (!(item = cbor_array_get(msg, 0))) {
		ctf_msg(ctf_alert, tof, "cbor_array_get(msg, 0) failed!\n");
		goto exit_free_tof;
	}
	if (!cbor_isa_uint(item)) {
		ctf_msg(ctf_alert, tof, "tof_msg_type cbor not a uint!\n");
		goto exit_free_tof;
	}
	tof->tof_msg_type = (enum tof_msg_type)cbor_get_int(item);
	if (!tof_valid_msg_type(tof->tof_msg_type)) {
		ctf_msg(ctf_alert, tof,
				"invalid msg type %d\n", tof->tof_msg_type);
		goto exit_free_tof;
	}
	switch (tof->tof_msg_type) {
	case tof_request:
		struct tof_request *request = &tof->tof_msg_body.request;
		cbor_item_t *blocking_cbor, *nr_obj_cbor;

		if (cbor_array_size(msg) < 2) {
			ctf_msg(ctf_alert, tof,
				     "cbor_array_size(msg) = %zd "
				     "too small\n", cbor_array_size(msg));
			goto exit_free_tof;
		}
		if (!(blocking_cbor = cbor_array_get(msg, 1))) {
			ctf_msg(ctf_alert, tof, "blocking_cbor = "
				     "cbor_array_get(msg, 1) failed!\n");
			goto exit_free_tof;
		}
		if (!cbor_is_bool(blocking_cbor)) {
			ctf_msg(ctf_alert, tof,
					"blocking_cbor not a bool!\n");
			goto exit_free_tof;
		}
		if (!(nr_obj_cbor = cbor_array_get(msg, 2))) {
			ctf_msg(ctf_alert, tof, "nr_obj_cbor = "
				     "cbor_array_get(msg, 2) failed!\n");
			goto exit_free_tof;
		}
		if (!tof_nr_obj_decode(nr_obj_cbor, &request->tof_nr_obj))
			goto exit_free_tof;
		request->tof_blocking = cbor_get_bool(blocking_cbor);
		break;
	case tof_done:
		/* This trace object type has no content apart from its
		 * existence and its type. */
		break;
	case tof_reply:
		unsigned k;
		struct tof_reply *reply = &tof->tof_msg_body.reply;

		if (cbor_array_size(msg) < 2) {
			ctf_msg(ctf_alert, tof,
					"reply msg array too small!\n");
			goto exit_free_tof;
		}
		/* refcount on reply_array acquired here: */
		if (!(reply_array = cbor_array_get(msg, 1))) {
			ctf_msg(ctf_alert, tof,
					"cbor_array_get() reply "
					"array failed!\n");
			goto exit_free_tof;
		}
		if (!cbor_isa_array(reply_array)) {
			ctf_msg(ctf_alert, tof,
					"reply array not of array type!\n");
			goto exit_free_reply;
		}
		reply->tof_nr_replies = cbor_array_size(reply_array);
		reply->tof_replies
			= g_rc_box_alloc0(reply->tof_nr_replies * sizeof(struct trace_object *));
		if (reply->tof_nr_replies > UINT16_MAX) {
			ctf_msg(ctf_alert, tof,
					"too many tof_nr_replies %zd\n",
					reply->tof_nr_replies);
			goto exit_free_reply;
		}
		for (k = 0; k < reply->tof_nr_replies; ++k) {
			cbor_item_t *array_entry;

			if (!(array_entry = cbor_array_get(reply_array, k))) {
				ctf_msg(ctf_alert, tof,
					"reply_array[%u] == NULL\n", k);
				goto exit_free_reply;
			}
			reply->tof_replies[k]
				= trace_object_decode(array_entry);
			ctf_cbor_decref(tof, &array_entry);
			if (!reply->tof_replies[k]) {
				ctf_msg(ctf_alert, tof,
						"reply->tof_replies[%u] "
						"decode failed!\n", k);
				cbor_describe(array_entry, stderr);
				ctf_cbor_decref(tof, &array_entry);
				goto exit_free_reply;
			}
		}
		/* cbor_decref(&reply_array); will happen eventually
		 * anyway upon falling through to the exit_free_reply
		 * label. */
		break;
	default:
		ctf_msg(ctf_alert, tof,
				"unrecognized tof_msg_type %d\n",
				tof->tof_msg_type);
		goto exit_free_tof;
	}
	if (!!tof)
		ctf_msg(ctf_debug, tof, "tof_decode() type %s succeeded\n",
				tof_msg_type_string(tof->tof_msg_type));
	else
		ctf_msg(ctf_alert, tof, "tof_decode() returned NULL\n");
	/* The caller is responsible for releasing refcounst on the input. */
	/* ctf_cbor_decref(tof, (cbor_item_t **)&msg); */
	return tof;
exit_free_reply:
	if (!!reply_array)
		ctf_cbor_decref(tof, &reply_array);
	else
		ctf_msg(ctf_alert, tof,
				"reply_array NULL at exit_free_reply\n");
exit_free_tof:
	ctf_msg(ctf_alert, tof,
			"error return, describing msg if non-NULL\n");
	if (!!msg) {
		if (0)
			cbor_describe((cbor_item_t *)msg, stderr);
		ctf_cbor_decref(tof, (cbor_item_t **)&msg);
	}
	tof_free(tof);
	return NULL;
}

void trace_object_free(struct trace_object *to)
{
	int k;

	if (!to)
		return;
	g_rc_box_release((void *)to->to_human);
	g_rc_box_release((void *)to->to_machine);
	for (k = 0; k < to->to_namespace_nr; ++k)
		g_rc_box_release((void *)to->to_namespace[k]);
	g_rc_box_release(to->to_namespace);
	g_rc_box_release((void *)to->to_hostname);
	g_rc_box_release((void *)to->to_thread_id);
}

static void
tof_free_members(void *p)
{
	struct tof_msg *tof = p;
	struct tof_reply *reply;
	int k;

	if (tof->tof_msg_type != tof_reply)
		return;
	reply = &tof->tof_msg_body.reply;
	for (k = 0; k < reply->tof_nr_replies; ++k)
		trace_object_free(reply->tof_replies[k]);
}

void tof_free(struct tof_msg *tof)
{
	g_rc_box_release_full(tof, tof_free_members);
}
