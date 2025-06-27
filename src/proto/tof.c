#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "handshake.h"
#include "tof.h"

/* TODO: error handling */

static bool
to_uint_array_get(const cbor_item_t *array, unsigned k, uintmax_t *val)
{
	bool ret = false;
	cbor_item_t *item = NULL;

	if (!(item = cbor_array_get(array, k)))
		return NULL;
	if (!cbor_is_null(item))
		goto out_uint_free;
	if (cbor_get_uint(item, val))
		ret = true;
	else if (cbor_isa_array(item)) {
		cbor_item_t *subarray = item;

		if (!(item = cbor_array_get(subarray, 0))) {
			cbor_decref(&subarray);
			goto out_uint_free;
		}
		if (cbor_get_uint(item, val))
			ret = true;
		cbor_decref(&subarray);
	}
out_uint_free:
	if (!!item)
		cbor_decref(&item);
	return ret;
}

static const char *
to_strdup_array_get(const cbor_item_t *array, unsigned k)
{
	cbor_item_t *item;
	const char *string, *new_string = NULL;

	if (!(item = cbor_array_get(array, k)))
		return NULL;
	if (!cbor_is_null(item))
		goto out_string_free;
	if (!cbor_isa_string(item))
		goto out_string_free;
	if (!(string = (const char *)cbor_string_handle(item)))
		goto out_string_free;
	if (!(new_string = strdup(string)))
		goto out_string_free;
out_string_free:
	cbor_decref(&item);
	return new_string;
}

struct trace_object *
trace_object_decode(const cbor_item_t *array)
{
	size_t k, n, nsub;
	uintmax_t val;
	struct trace_object *to;
	cbor_item_t *subarray;

	if (!(to = calloc(1, sizeof(struct trace_object))))
		return NULL;

	if (!cbor_isa_array(array))
		goto out_free_to;
	if ((n = cbor_array_size(array)) != 9)
		ctf_msg(tof, "unexpected trace_object array length %d\n", n);
	if (!(subarray = cbor_array_get(array, 1)))
		goto out_free_to;
	if (cbor_is_null(subarray)) {
		ctf_msg(tof, "null subarray\n");
		cbor_decref(&subarray);
		goto out_free_to;
	}
	if (!cbor_isa_array(subarray)) {
		ctf_msg(tof, "subarray not an array\n");
		cbor_decref(&subarray);
		goto out_free_to;
	}
	if ((nsub = cbor_array_size(subarray)) < 1) {
		ctf_msg(tof, "subarray size %d\n", nsub);
		cbor_decref(&subarray);
		goto out_free_to;
	}

	if (!(to->to_human = to_strdup_array_get(array, 0)))
		goto out_free_to;
	if (!(to->to_machine = to_strdup_array_get(array, 2)))
		goto out_free_human;

	if (!(subarray = cbor_array_get(array, 3)))
		goto out_free_machine;
	if (!cbor_isa_array(subarray)) {
		cbor_decref(&subarray);
		goto out_free_machine;
	}
	/* tags don't get used in this case */
	to->to_namespace_nr = cbor_array_size(subarray);
	if (!(to->to_namespace = calloc(to->to_namespace_nr, sizeof(char *)))) {
		cbor_decref(&subarray);
		goto out_free_machine;
	}
	for (k = 0; k < to->to_namespace_nr; ++k) {
		if (!!(to->to_namespace[k] = to_strdup_array_get(subarray, k)))
			continue;
		cbor_decref(&subarray);
		goto out_free_namespace_entries;
	}

	if (!to_uint_array_get(array, 4, &val))
		goto out_free_namespace_entries;
	to->to_severity = (enum severity_s)val;

	if (!to_uint_array_get(array, 5, &val))
		goto out_free_namespace_entries;
	to->to_details = (enum detail_level)val;

	if (!to_uint_array_get(array, 6, &val))
		goto out_free_namespace_entries;
	to->to_timestamp = (time_t)val;

	if (!(to->to_hostname = to_strdup_array_get(array, 7)))
		goto out_free_namespace_entries;
	if (!(to->to_thread_id = to_strdup_array_get(array, 8)))
		goto out_free_hostname;
	return to;
out_free_hostname:
	free((void *)to->to_hostname);
out_free_namespace_entries:
	for (k = 0; k < to->to_namespace_nr; ++k)
		free((void *)to->to_namespace[k]);
	free(to->to_namespace);
out_free_machine:
	free((void *)to->to_machine);
out_free_human:
	free((void *)to->to_human);
out_free_to:
	free(to);
	return NULL;
}

cbor_item_t *
trace_object_encode(const struct trace_object *trace_object)
{
	int k;
	cbor_item_t *array, *human_array;
	cbor_item_t *human, *machine, *namespace, *severity,
		    *details, *timestamp, *hostname, *thread_id;

	if (!(array = cbor_new_definite_array(8)))
		return NULL;
	if (!trace_object->to_human)
		human = cbor_new_null();
	else
		human = cbor_build_string(trace_object->to_human);
	if (!human)
		goto out_free_array;
	if (!(human_array = cbor_new_definite_array(1))) {
		cbor_decref(&human);
		goto out_free_array;
	}
	if (!cbor_array_set(human_array, 0, human)) {
		cbor_decref(&human);
		goto out_free_human_array;
	}
	if (!cbor_array_set(array, 1, human_array))
		goto out_free_human_array;
	if (!(machine = cbor_build_string(trace_object->to_machine)))
		goto out_free_array;
	if (!cbor_array_set(array, 1, machine))
		goto out_free_machine;
	namespace = cbor_new_definite_array(trace_object->to_namespace_nr);
	if (!namespace)
		goto out_free_array;
	for (k = 0; k < trace_object->to_namespace_nr; ++k) {
		cbor_item_t *item;

		if (!(item = cbor_build_string(trace_object->to_namespace[k])))
			goto out_free_namespace;
		if (!cbor_array_set(namespace, k, item)) {
			cbor_decref(&item);
			goto out_free_namespace;
		}
	}
	if (!cbor_array_set(array, 2, namespace))
		goto out_free_namespace;
	if (!(severity = cbor_new_int32()))
		goto out_free_array;
	cbor_set_uint32(severity, trace_object->to_severity);
	if (!cbor_array_set(array, 3, severity))
		goto out_free_severity;
	if (!(details = cbor_new_int32()))
		goto out_free_array;
	cbor_set_uint32(details, trace_object->to_details);
	if (!cbor_array_set(array, 4, details))
		goto out_free_details;
	if (!(timestamp = cbor_build_uint64(trace_object->to_timestamp)))
		goto out_free_array;
	if (!cbor_array_set(array, 5, timestamp))
		goto out_free_timestamp;
	if (!(hostname = cbor_build_string(trace_object->to_hostname)))
		goto out_free_array;
	if (!cbor_array_set(array, 6, hostname))
		goto out_free_hostname;
	if (!(thread_id = cbor_build_string(trace_object->to_thread_id)))
		goto out_free_array;
	if (!cbor_array_set(array, 7, thread_id))
		goto out_free_thread_id;
	return array;
	/*
	 * array holds the reference counts for all of the array entries.
	 * Falling through would be a double refcount release. The
	 * individual components' labels are for failures to link into
	 * the larger structures holding references to them.
	 */
out_free_human_array:
	cbor_decref(&human_array);
	goto out_free_array;
out_free_machine:
	cbor_decref(&machine);
	goto out_free_array;
out_free_namespace:
	cbor_decref(&namespace);
	goto out_free_array;
out_free_severity:
	cbor_decref(&severity);
	goto out_free_array;
out_free_details:
	cbor_decref(&details);
	goto out_free_array;
out_free_timestamp:
	cbor_decref(&timestamp);
	goto out_free_array;
out_free_hostname:
	cbor_decref(&hostname);
	goto out_free_array;
out_free_thread_id:
	cbor_decref(&thread_id);
	goto out_free_array;
out_free_array:
	cbor_decref(&array);
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
			ctf_msg(tof, "msg_array allocation failed!\n");
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
			ctf_msg(tof, "msg_array allocation failed!\n");
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
		cbor_decref(&tof_nr_obj);
		goto out_free_msg_array;
	out_free_tof_blocking:
		cbor_decref(&tof_blocking);
		goto out_free_msg_array;

	case tof_reply:
		const struct tof_reply *reply = &msg->tof_msg_body.reply;
		unsigned k;

		if (!(msg_array = cbor_new_definite_array(2))) {
			ctf_msg(tof, "msg_array allocation failed!\n");
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
				ctf_msg(tof, "trace_object_encode()"
					     "failed on reply->"
					     "tof_replies[%u]\n", k);
				goto out_free_reply_array;
				break;
			}
			if (cbor_array_set(reply_array, k, reply_array_entry))
				continue;
			cbor_decref(&reply_array_entry);
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
	cbor_decref(&reply_array);
	goto out_free_msg_array;
out_free_msg_type:
	cbor_decref(&msg_type);
	goto out_free_msg_array;
out_free_msg_array:
	cbor_decref(&msg_array);
	return NULL;
}

bool
tof_valid_msg_type(const enum tof_msg_type type)
{
	switch (type) {
	case tof_request /* == 1 */:
	case tof_done    /* == 2 */:
	case tof_reply   /* == 3 */:
		return true;
	default:
		if (type == 0)
			ctf_msg(tof, "tof_msg_type 0 seen!\n");
		else
			ctf_msg(tof, "unrecognized tof_msg_type %d "
					"seen!\n", type);
		return false;
	}
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
		ctf_msg(tof, "nr_obj too large (32-bit)!\n");
		return false;
	case CBOR_INT_64:
		if (cbor_get_uint64(nr_obj_item) <= UINT16_MAX) {
			*val = cbor_get_uint64(nr_obj_item);
			return true;
		}
		ctf_msg(tof, "nr_obj too large (64-bit)!\n");
		return false;
	default:
		ctf_msg(tof, "unrecognized nr_obj integer width\n");
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
		ctf_msg(tof, "nr_obj array size = %zd != 2!\n",
				cbor_array_size(nr_obj_item));
		return false;
	}
	if (!(lower = cbor_array_get(nr_obj_item, 0))) {
		ctf_msg(tof, "cbor_array_get(nr_obj_item, 0) failed!\n");
		return false;
	}
	if (!(upper = cbor_array_get(nr_obj_item, 1))) {
		ctf_msg(tof, "cbor_array_get(nr_obj_item, 1) failed!\n");
		cbor_decref(&lower);
		return false;
	}
	ret = ret && tof_nr_obj_decode_uint(lower, &lower_val);
	ret = ret && tof_nr_obj_decode_uint(upper, val);
	ret = ret && !!(lower_val == 0);
	cbor_decref(&lower);
	cbor_decref(&upper);
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
		ctf_msg(tof, "nr_obj of negint type!\n");
		return false;
	case CBOR_TYPE_BYTESTRING:
		ctf_msg(tof, "nr_obj of bytestring type!\n");
		return false;
	case CBOR_TYPE_STRING:
		ctf_msg(tof, "nr_obj of string type!\n");
		return false;
	case CBOR_TYPE_MAP:
		ctf_msg(tof, "nr_obj of map type!\n");
		return false;
	case CBOR_TYPE_TAG:
		ctf_msg(tof, "nr_obj of tag type!\n");
		return false;
	case CBOR_TYPE_FLOAT_CTRL:
		ctf_msg(tof, "nr_obj of float_ctrl type!\n");
		return false;
	default:
		ctf_msg(tof, "nr_obj of unrecognized type!\n");
		return false;
	}
}

struct tof_msg *
tof_decode(const cbor_item_t *msg)
{
	struct tof_msg *tof = calloc(1, sizeof(struct tof_msg));
	cbor_item_t *item, *reply_array = NULL;

	ctf_msg(tof, "entered tof_decode()\n");
	if (!msg) {
		ctf_msg(tof, "NULL msg!\n");
		return NULL;
	}
	cbor_describe((cbor_item_t *)msg, stderr);
	if (!tof) {
		ctf_msg(tof, "tof allocation failed!\n");
		return NULL;
	}
	if (!cbor_isa_array(msg)) {
		ctf_msg(tof, "cbor msg not an array!\n");
		goto exit_free_tof;
	}
	if (cbor_array_size(msg) < 1) {
		ctf_msg(tof, "cbor msg is an empty array, no type!\n");
		goto exit_free_tof;
	}
	if (!(item = cbor_array_get(msg, 0))) {
		ctf_msg(tof, "cbor_array_get(msg, 0) failed!\n");
		goto exit_free_tof;
	}
	if (!cbor_isa_uint(item)) {
		ctf_msg(tof, "tof_msg_type cbor not a uint!\n");
		goto exit_free_tof;
	}
	tof->tof_msg_type = (enum tof_msg_type)cbor_get_int(item);
	if (!tof_valid_msg_type(tof->tof_msg_type)) {
		ctf_msg(tof, "invalid msg type %d\n", tof->tof_msg_type);
		goto exit_free_tof;
	}
	switch (tof->tof_msg_type) {
	case tof_request:
		struct tof_request *request = &tof->tof_msg_body.request;
		cbor_item_t *blocking_cbor, *nr_obj_cbor;

		if (cbor_array_size(msg) < 2) {
			ctf_msg(tof, "cbor_array_size(msg) = %zd "
				     "too small\n", cbor_array_size(msg));
			goto exit_free_tof;
		}
		if (!(blocking_cbor = cbor_array_get(msg, 1))) {
			ctf_msg(tof, "blocking_cbor = "
				     "cbor_array_get(msg, 1) failed!\n");
			goto exit_free_tof;
		}
		if (!cbor_is_bool(blocking_cbor)) {
			ctf_msg(tof, "blocking_cbor not a bool!\n");
			goto exit_free_tof;
		}
		if (!(nr_obj_cbor = cbor_array_get(msg, 2))) {
			ctf_msg(tof, "nr_obj_cbor = "
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
			ctf_msg(tof, "reply msg array too small!\n");
			goto exit_free_tof;
		}
		if (!(reply_array = cbor_array_get(msg, 1))) {
			ctf_msg(tof, "cbor_array_get() reply array failed!\n");
			goto exit_free_tof;
		}
		if (!cbor_isa_array(reply_array)) {
			ctf_msg(tof, "reply array not of array type!\n");
			goto exit_free_reply;
		}
		reply->tof_nr_replies = cbor_array_size(reply_array);
		reply->tof_replies
			= calloc(reply->tof_nr_replies,
					sizeof(struct trace_object *));
		if (reply->tof_nr_replies > UINT16_MAX) {
			ctf_msg(tof, "too many tof_nr_replies %zd\n",
					reply->tof_nr_replies);
			goto exit_free_reply;
		}
		for (k = 0; k < reply->tof_nr_replies; ++k) {
			cbor_item_t *array_entry;

			if (!(array_entry = cbor_array_get(reply_array, k))) {
				ctf_msg(tof,  "reply_array[%u] == NULL\n", k);
				goto exit_free_reply;
			}
			reply->tof_replies[k]
				= trace_object_decode(array_entry);
			cbor_decref(&array_entry);
			if (!reply->tof_replies[k]) {
				ctf_msg(tof, "reply->tof_replies[%u] "
						"decode failed!\n", k);
				goto exit_free_reply;
			}
		}
		cbor_decref(&reply_array);
		break;
	default:
		ctf_msg(tof, "unrecognized tof_msg_type %d\n", tof->tof_msg_type);
		goto exit_free_tof;
	}
	if (!!tof)
		ctf_msg(tof, "tof_decode() succeeded\n");
	else
		ctf_msg(tof, "tof_decode() returned NULL\n");
	cbor_decref((cbor_item_t **)&msg);
	return tof;
exit_free_reply:
	if (!!reply_array)
		cbor_decref(&reply_array);
exit_free_tof:
	ctf_msg(tof, "error return, describing msg if non-NULL\n");
	if (!!msg) {
		cbor_describe((cbor_item_t *)msg, stderr);
		cbor_decref((cbor_item_t **)&msg);
	}
	tof_free(tof);
	return NULL;
}

void trace_object_free(struct trace_object *to)
{
	int k;

	free((void *)to->to_human);
	free((void *)to->to_machine);
	for (k = 0; k < to->to_namespace_nr; ++k)
		free((void *)to->to_namespace[k]);
	free(to->to_namespace);
	free((void *)to->to_hostname);
	free((void *)to->to_thread_id);
}

void tof_free(struct tof_msg *tof)
{
	struct tof_reply *reply;
	int k;

	if (tof->tof_msg_type != tof_reply)
		goto exit_free_tof;
	reply = &tof->tof_msg_body.reply;
	for (k = 0; k < reply->tof_nr_replies; ++k)
		trace_object_free(reply->tof_replies[k]);
exit_free_tof:
	free(tof);
}
