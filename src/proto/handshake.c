#include <cbor.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "handshake.h"

cbor_item_t *
cbor_build_encode_word(uint64_t value)
{
	if (value < 1ULL << 8)
		return cbor_build_uint8(value);
	else if (value < 1ULL << 16)
		return cbor_build_uint16(value);
	else if (value < 1ULL << 32)
		return cbor_build_uint32(value);
	else
		return cbor_build_uint64(value);
}

static struct handshake *
propose_versions_decode(const cbor_item_t *msg_array, struct handshake *handshake)
{
	struct handshake_propose_versions *propose_versions;
	cbor_item_t *version_map;
	struct cbor_pair *version_array;
	unsigned k;

	propose_versions = &handshake->handshake_message.propose_versions;
	version_map = cbor_array_get(msg_array, 1);
	version_array = cbor_map_handle(version_map);
	propose_versions->handshake_propose_versions_len
		= cbor_map_size(version_map);
	propose_versions->handshake_propose_versions
		= calloc(propose_versions->handshake_propose_versions_len,
			sizeof(struct handshake_propose_version_pair));
	for (k = 0; k < propose_versions->handshake_propose_versions_len; ++k) {
		struct handshake_propose_version_pair *pair
			= &propose_versions->handshake_propose_versions[k];

		pair->propose_version_key = cbor_get_int(version_array[k].key);
		pair->propose_version_value = version_array[k].value;
	}
	return handshake;
}

static struct handshake *
accept_version_decode(const cbor_item_t *msg_array, struct handshake *handshake)
{
	struct handshake_accept_version *accept_version;

	accept_version = &handshake->handshake_message.accept_version;
	accept_version->handshake_accept_version_number
		= cbor_get_int(cbor_array_get(msg_array, 1));
	accept_version->handshake_accept_version_params
		= cbor_array_get(msg_array, 2);
	return handshake;
}

static struct handshake *
version_mismatch_decode(const cbor_item_t *refusal_array, struct handshake *handshake)
{
	cbor_item_t *mismatch_array;
	struct handshake_refusal_version_mismatch *mismatch;
	struct handshake_refusal *refusal;
	unsigned k;

	refusal = &handshake->handshake_message.refusal;
	mismatch_array = cbor_array_get(refusal_array, 1);
	mismatch = &refusal->refusal_message.version_mismatch;
	mismatch->handshake_refusal_version_mismatch_len
		= cbor_array_size(mismatch_array);
	mismatch->handshake_refusal_version_mismatch_versions
		= calloc(mismatch->handshake_refusal_version_mismatch_len,
				sizeof(uint64_t *));
	for (k = 0; k < mismatch->handshake_refusal_version_mismatch_len; ++k)
		mismatch->handshake_refusal_version_mismatch_versions[k]
			= cbor_get_int(cbor_array_get(mismatch_array, k));
	return handshake;
}

static struct handshake *
decode_error_decode(const cbor_item_t *refusal_array, struct handshake *handshake)
{
	struct handshake_refusal *refusal;
	struct handshake_refusal_decode_error *decode_error;

	refusal = &handshake->handshake_message.refusal;
	decode_error = &refusal->refusal_message.decode_error;
	decode_error->handshake_refusal_decode_error_version
		= cbor_get_int(cbor_array_get(refusal_array, 1));
	decode_error->handshake_refusal_decode_error_string
		= strdup((char *)cbor_string_handle(cbor_array_get(refusal_array, 2)));
	return handshake;
}

static struct handshake *
refused_decode(const cbor_item_t *refusal_array, struct handshake *handshake)
{
	struct handshake_refusal *refusal;
	struct handshake_refusal_refused *refused;

	refusal = &handshake->handshake_message.refusal;
	refused = &refusal->refusal_message.refused;
	refused->handshake_refusal_refused_version
		= cbor_get_int(cbor_array_get(refusal_array, 1));
	refused->handshake_refusal_refused_string
		= strdup((char *)cbor_string_handle(cbor_array_get(refusal_array, 2)));
	return handshake;
}

static struct handshake *
refusal_decode(const cbor_item_t *msg_array, struct handshake *handshake)
{
	struct handshake_refusal *refusal;
	enum handshake_refusal_reason_type reason_type;
	cbor_item_t *refusal_array;

	refusal_array = cbor_array_get(msg_array, 1);
	refusal = &handshake->handshake_message.refusal;
	reason_type = cbor_get_int(cbor_array_get(refusal_array, 0));
	refusal->reason_type = reason_type;
	switch (reason_type) {
	case handshake_refusal_version_mismatch:
		return version_mismatch_decode(refusal_array, handshake);
	case handshake_refusal_decode_error:
		return decode_error_decode(refusal_array, handshake);
	case handshake_refusal_refused:
		return refused_decode(refusal_array, handshake);
	}
	return handshake;
}

static struct handshake *
query_reply_decode(const cbor_item_t *msg_array, struct handshake *handshake)
{
	struct handshake_query_reply *query_reply;
	cbor_item_t *version_map;
	struct cbor_pair *version_array;
	unsigned k;

	query_reply = &handshake->handshake_message.query_reply;
	version_map = cbor_array_get(msg_array, 1);
	version_array = cbor_map_handle(version_map);
	query_reply->handshake_query_reply_len
		= cbor_map_size(version_map);
	query_reply->handshake_query_reply
		= calloc(query_reply->handshake_query_reply_len,
			sizeof(struct handshake_query_reply_pair));
	for (k = 0; k < query_reply->handshake_query_reply_len; ++k) {
		struct handshake_query_reply_pair *pair
			= &query_reply->handshake_query_reply[k];

		pair->query_reply_key
			= cbor_get_int(version_array[k].key);
		pair->query_reply_value = version_array[k].value;
	}
	return handshake;
}

struct handshake *
handshake_decode(const cbor_item_t *msg_array)
{
	struct handshake *handshake = NULL;

	handshake = calloc(1, sizeof(struct handshake));
	handshake->handshake_type
		= cbor_get_int(cbor_array_get(msg_array, 0));
	switch (handshake->handshake_type) {
	case handshake_propose_versions:
		return propose_versions_decode(msg_array, handshake);
	case handshake_accept_version:
		return accept_version_decode(msg_array, handshake);
	case handshake_refusal:
		return refusal_decode(msg_array, handshake);
	case handshake_query_reply:
		return query_reply_decode(msg_array, handshake);
	}
	return handshake;
}

static cbor_item_t *
propose_versions_encode(const struct handshake_propose_versions *propose_versions)
{
	cbor_item_t *type_tag, *versions_map, *item;
	unsigned k;

	item = cbor_new_definite_array(2);
	if (!item)
		return NULL;
	if (!(type_tag = cbor_build_encode_word(handshake_propose_versions)))
		goto exit_free_item;
	if (!cbor_array_set(item, 0, type_tag)) {
		cbor_decref(&type_tag);
		goto exit_free_item;
	}
	if (!(versions_map = cbor_new_definite_array(propose_versions->handshake_propose_versions_len)))
		goto exit_free_item;
	if (!cbor_array_set(item, 1, versions_map)) {
		cbor_decref(&versions_map);
		goto exit_free_item;
	}
	for (k = 0; k < propose_versions->handshake_propose_versions_len; ++k) {
		struct cbor_pair pair;
		struct handshake_propose_version_pair *elem;

		elem = &propose_versions->handshake_propose_versions[k];
		if (!(pair.key = cbor_build_encode_word(elem->propose_version_key)))
			goto exit_free_item;
		pair.value = elem->propose_version_value;
		if (!cbor_map_add(versions_map, pair)) {
			cbor_decref(&pair.key);
			goto exit_free_item;
		}
	}
	return item;
exit_free_item:
	cbor_decref(&item);
	return NULL;
}

static cbor_item_t *
accept_version_encode(const struct handshake_accept_version *accept_version)
{
	cbor_item_t *item;

	item = cbor_new_definite_array(3);
	(void)!cbor_array_set(item, 0, cbor_build_encode_word(handshake_accept_version));
	(void)!cbor_array_set(item, 1, cbor_build_encode_word(accept_version->handshake_accept_version_number));
	(void)!cbor_array_set(item, 2, accept_version->handshake_accept_version_params);
	return item;
}

static cbor_item_t *
version_mismatch_encode(const struct handshake_refusal_version_mismatch *version_mismatch)
{
	cbor_item_t *reason, *versions;
	unsigned k;

	reason = cbor_new_definite_array(2);
	(void)!cbor_array_set(reason, 0, cbor_build_encode_word(handshake_refusal_version_mismatch));
	versions = cbor_new_definite_array(version_mismatch->handshake_refusal_version_mismatch_len);
	for (k = 0; k < version_mismatch->handshake_refusal_version_mismatch_len; ++k)
		(void)!cbor_array_set(versions, k, cbor_build_encode_word(version_mismatch->handshake_refusal_version_mismatch_versions[k]));
	(void)!cbor_array_set(reason, 1, versions);
	return reason;
}

static cbor_item_t *
decode_error_encode(const struct handshake_refusal_decode_error *decode_error)
{
	cbor_item_t *reason;

	reason = cbor_new_definite_array(3);
	(void)!cbor_array_set(reason, 0, cbor_build_encode_word(handshake_refusal_decode_error));
	(void)!cbor_array_set(reason, 1, cbor_build_encode_word(decode_error->handshake_refusal_decode_error_version));
	(void)!cbor_array_set(reason, 2, cbor_build_string(decode_error->handshake_refusal_decode_error_string));
	return reason;
}

static cbor_item_t *
refused_encode(const struct handshake_refusal_refused *refused)
{
	cbor_item_t *reason;

	reason = cbor_new_definite_array(3);
	(void)!cbor_array_set(reason, 0, cbor_build_encode_word(handshake_refusal_refused));
	(void)!cbor_array_set(reason, 1, cbor_build_encode_word(refused->handshake_refusal_refused_version));
	(void)!cbor_array_set(reason, 2, cbor_build_string(refused->handshake_refusal_refused_string));
	return reason;
}

static cbor_item_t *
refusal_encode(const struct handshake_refusal *refusal)
{
	cbor_item_t *item;

	item = cbor_new_definite_array(2);
	/* The array length varies by reason_type */
	(void)!cbor_array_set(item, 0, cbor_build_encode_word(handshake_refusal));
	switch (refusal->reason_type) {
	case handshake_refusal_version_mismatch:
		(void)!cbor_array_set(item, 1, version_mismatch_encode(&refusal->refusal_message.version_mismatch));
		break;
	case handshake_refusal_decode_error:
		(void)!cbor_array_set(item, 1, decode_error_encode(&refusal->refusal_message.decode_error));
		break;
	case handshake_refusal_refused:
		(void)!cbor_array_set(item, 1, refused_encode(&refusal->refusal_message.refused));
		break;
	}
	return item;
}

static cbor_item_t *
query_reply_encode(const struct handshake_query_reply *query_reply)
{
	cbor_item_t *versions_map, *item;
	unsigned k;

	item = cbor_new_definite_array(2);
	(void)!cbor_array_set(item, 0, cbor_build_encode_word(handshake_query_reply));
	versions_map = cbor_new_definite_array(query_reply->handshake_query_reply_len);
	(void)!cbor_array_set(item, 1, versions_map);
	for (k = 0; k < query_reply->handshake_query_reply_len; ++k) {
		struct cbor_pair pair;
		struct handshake_query_reply_pair *elem;

		elem = &query_reply->handshake_query_reply[k];
		pair.key = cbor_build_encode_word(elem->query_reply_key);
		pair.value = elem->query_reply_value;
		(void)!cbor_map_add(versions_map, pair);
	}
	(void)!cbor_array_set(item, 1, versions_map);
	return item;
}

cbor_item_t *
handshake_encode(const struct handshake *handshake)
{
	switch (handshake->handshake_type) {
	case handshake_propose_versions:
		return propose_versions_encode(&handshake->handshake_message.propose_versions);
	case handshake_accept_version:
		return accept_version_encode(&handshake->handshake_message.accept_version);
	case handshake_refusal:
		return refusal_encode(&handshake->handshake_message.refusal);
	case handshake_query_reply:
		return query_reply_encode(&handshake->handshake_message.query_reply);
	}
	return NULL;
}
