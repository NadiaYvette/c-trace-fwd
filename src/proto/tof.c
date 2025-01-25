#include <cbor.h>
#include "tof.h"
#include "c_trace_fwd.h"
#include "handshake.h"

/* TODO: error handling */

struct trace_object *
trace_object_decode(cbor_item_t *array)
{
	int k;
	struct trace_object *to;
	cbor_item_t *item;

	to = calloc(1, sizeof(struct trace_object));
	if (!to)
		return NULL;
	item = cbor_array_get(array, 0);
	if (cbor_is_null(item))
		to->to_human = NULL;
	else
		to->to_human = strdup((const char *)cbor_string_handle(item));
	item = cbor_array_get(array, 1);
	to->to_machine = strdup((const char *)cbor_string_handle(item));
	item = cbor_array_get(array, 2);
	to->to_namespace_nr = cbor_array_size(item);
	to->to_namespace = calloc(to->to_namespace_nr, sizeof(char *));
	for (k = 0; k < to->to_namespace_nr; ++k)
		to->to_namespace[k] = strdup((const char *)cbor_string_handle(cbor_array_get(item, k)));
	item = cbor_array_get(array, 3);
	to->to_severity = cbor_get_uint32(item);
	item = cbor_array_get(array, 4);
	to->to_details = cbor_get_uint32(item);
	item = cbor_array_get(array, 5);
	to->to_timestamp = cbor_get_uint64(item);
	item = cbor_array_get(array, 6);
	to->to_hostname = strdup((const char *)cbor_string_handle(item));
	item = cbor_array_get(array, 7);
	to->to_thread_id = strdup((const char *)cbor_string_handle(item));
	return to;
}

cbor_item_t *
trace_object_encode(const struct trace_object *trace_object)
{
	int k;
	cbor_item_t *array;
	cbor_item_t *human, *machine, *namespace, *severity,
		    *details, *timestamp, *hostname, *thread_id;

	array = cbor_new_definite_array(8);
	if (!array)
		return NULL;
	if (trace_object->to_human)
		human = cbor_new_null();
	else
		human = cbor_build_string(trace_object->to_human);
	(void)!cbor_array_set(array, 0, human);
	machine = cbor_build_string(trace_object->to_machine);
	(void)!cbor_array_set(array, 1, machine);
	namespace = cbor_new_definite_array(trace_object->to_namespace_nr);
	for (k = 0; k < trace_object->to_namespace_nr; ++k) {
		cbor_item_t *item;

		item = cbor_build_string(trace_object->to_namespace[k]);
		if (!item)
			return NULL;
		(void)!cbor_array_set(namespace, k, item);
	}
	(void)!cbor_array_set(array, 2, namespace);
	severity = cbor_new_int32();
	cbor_set_uint32(severity, trace_object->to_severity);
	(void)!cbor_array_set(array, 3, severity);
	details = cbor_new_int32();
	cbor_set_uint32(details, trace_object->to_details);
	(void)!cbor_array_set(array, 4, details);
	timestamp = cbor_build_uint64(trace_object->to_timestamp);
	(void)!cbor_array_set(array, 5, timestamp);
	hostname = cbor_build_string(trace_object->to_hostname);
	(void)!cbor_array_set(array, 6, hostname);
	thread_id = cbor_build_string(trace_object->to_thread_id);
	(void)!cbor_array_set(array, 7, thread_id);
	return array;
}

cbor_item_t *
tof_encode(const struct tof_msg *msg)
{
	cbor_item_t *msg_type, *msg_array = NULL;

	switch (msg->tof_msg_type) {
	case tof_done:
		msg_array = cbor_new_definite_array(1);
		msg_type = cbor_build_uint32(tof_done);
		(void)!cbor_array_set(msg_array, 0, msg_type);
		break;

	case tof_request:
		const struct tof_request *request = &msg->tof_msg_body.request;
		cbor_item_t *tof_nr_obj, *tof_blocking;

		msg_array = cbor_new_definite_array(3);
		msg_type = cbor_build_uint32(tof_request);
		(void)!cbor_array_set(msg_array, 0, msg_type);
		tof_blocking = cbor_build_bool(request->tof_blocking);
		(void)!cbor_array_set(msg_array, 1, tof_blocking);
		tof_nr_obj = cbor_build_uint16(request->tof_nr_obj);
		(void)!cbor_array_set(msg_array, 2, tof_nr_obj);
		break;

	case tof_reply:
		const struct tof_reply *reply = &msg->tof_msg_body.reply;
		cbor_item_t *reply_array;

		msg_array = cbor_new_definite_array(2);
		msg_type = cbor_build_uint32(tof_reply);
		(void)!cbor_array_set(msg_array, 0, msg_type);
		reply_array = cbor_new_definite_array(reply->tof_nr_replies);
		(void)!cbor_array_set(msg_array, 1, reply_array);
		break;
	}
	return msg_array;
}

struct tof_msg *
tof_decode(const cbor_item_t *msg)
{
	struct tof_msg *tof = calloc(1, sizeof(struct tof_msg));
	cbor_item_t *item;

	if (!tof)
		return NULL;
	if (!(item = cbor_array_get(msg, 0)))
		goto exit_free_tof;
	tof->tof_msg_type = (enum tof_msg_type)cbor_get_encode_word(item);
	switch (tof->tof_msg_type) {
	case tof_request:
		struct tof_request *request = &tof->tof_msg_body.request;

		request->tof_blocking = cbor_get_bool(cbor_array_get(msg, 1));
		request->tof_nr_obj = cbor_get_uint16(cbor_array_get(msg, 2));
		break;
	case tof_done:
		break;
	case tof_reply:
		int k;
		struct tof_reply *reply = &tof->tof_msg_body.reply;
		cbor_item_t *reply_array = cbor_array_get(msg, 1);

		reply->tof_nr_replies = cbor_array_size(reply_array);
		reply->tof_replies = calloc(reply->tof_nr_replies, sizeof(struct trace_object *));
		for (k = 0; k < reply->tof_nr_replies; ++k)
			reply->tof_replies[k] = trace_object_decode(cbor_array_get(reply_array, k));
		break;
	}
	return tof;
exit_free_tof:
	tof_free(tof);
	return NULL;
}

void trace_object_free(struct trace_object *to)
{
	int k;

	free(to->to_human);
	free(to->to_machine);
	for (k = 0; k < to->to_namespace_nr; ++k)
		free(to->to_namespace[k]);
	free(to->to_hostname);
	free(to->to_thread_id);
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
