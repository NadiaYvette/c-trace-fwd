#include <cbor.h>
#include <cbor/ints.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ctf_util.h"
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

bool
cbor_get_uint(const cbor_item_t *item, uintmax_t *value)
{
	if (cbor_typeof(item) != CBOR_TYPE_UINT) {
		ctf_msg(handshake, "item %d not UINT\n", cbor_typeof(item));
		cbor_describe((cbor_item_t *)item, stderr);
		return false;
	}
	switch (cbor_int_get_width(item)) {
	case CBOR_INT_8:
		*value = (uintmax_t)cbor_get_uint8(item);
		break;
	case CBOR_INT_16:
		*value = (uintmax_t)cbor_get_uint16(item);
		break;
	case CBOR_INT_32:
		*value = (uintmax_t)cbor_get_uint32(item);
		break;
	case CBOR_INT_64:
		*value = (uintmax_t)cbor_get_uint64(item);
		break;
	default:
		ctf_msg(handshake, "unrecognized uint width\n");
		cbor_describe((cbor_item_t *)item, stderr);
		return false;
	}
	return true;
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
				sizeof(uint64_t));
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
	cbor_item_t *type_cbor;
	struct handshake *handshake = NULL;

	if (!(handshake = calloc(1, sizeof(struct handshake))))
		return NULL;
	if (!(type_cbor = cbor_array_get(msg_array, 0)))
		goto out_free_handshake;
	handshake->handshake_type = cbor_get_int(type_cbor);
	ctf_cbor_decref(handshake, &type_cbor);
	switch (handshake->handshake_type) {
	case handshake_propose_versions:
		return propose_versions_decode(msg_array, handshake);
	case handshake_accept_version:
		return accept_version_decode(msg_array, handshake);
	case handshake_refusal:
		return refusal_decode(msg_array, handshake);
	case handshake_query_reply:
		return query_reply_decode(msg_array, handshake);
	default:
		goto out_free_handshake;
	}
	return handshake;
out_free_handshake:
	free(handshake);
	return NULL;
}

void
handshake_free(struct handshake *handshake)
{
	union handshake_message *msg = &handshake->handshake_message;

	switch (handshake->handshake_type) {
	case handshake_propose_versions:
		struct handshake_propose_versions *hpv;

		hpv = &msg->propose_versions;
		free(hpv->handshake_propose_versions);
		break;
	case handshake_accept_version:
		struct handshake_accept_version *hav;

		hav = &msg->accept_version;
		ctf_cbor_decref(handshake, &hav->handshake_accept_version_params);
		break;
	case handshake_query_reply:
		struct handshake_query_reply *hqr = &msg->query_reply;

		free(hqr->handshake_query_reply);
		break;
	case handshake_refusal:
		struct handshake_refusal *hr = &msg->refusal;

		switch (hr->reason_type) {
		case handshake_refusal_version_mismatch:
			free(hr->refusal_message.version_mismatch.handshake_refusal_version_mismatch_versions);
			break;
		case handshake_refusal_decode_error:
			free(hr->refusal_message.decode_error.handshake_refusal_decode_error_string);
			break;
		case handshake_refusal_refused:
			free(hr->refusal_message.refused.handshake_refusal_refused_string);
			break;
		default:
			ctf_msg(handshake, "unrecognized handshake refusal\n");
		}
		break;
	default:
		ctf_msg(handshake, "freeing handshake of unrecognized type\n");
	}
	free(handshake);
}

static cbor_item_t *
propose_versions_encode(const struct handshake_propose_versions *propose_versions)
{
	cbor_item_t *proposal_array, *proposal_map, *array_zero_element;
	struct handshake_propose_version_pair *handshake_propose_versions
		= propose_versions->handshake_propose_versions;
	unsigned k, len
		= (unsigned)propose_versions->handshake_propose_versions_len;

	if (!(proposal_array = cbor_new_definite_array(2)))
		return NULL;
	if (!(array_zero_element = cbor_build_encode_word(0)))
		goto out_free_proposal_array;
	if (!cbor_array_set(proposal_array, 0, array_zero_element))
		goto out_free_array_zero_element;
	ctf_msg(handshake, "about to build proposal map\n");
	if (!(proposal_map = cbor_new_definite_map(propose_versions->handshake_propose_versions_len))) {
		ctf_msg(handshake, "allocation of proposal map of length "
				   "%zd failed!\n",
				   propose_versions->handshake_propose_versions_len);
		goto out_free_array_zero_element;
	}
	ctf_msg(handshake, "about to check proposal map type\n");
	if (cbor_typeof(proposal_map) != CBOR_TYPE_MAP) {
		ctf_msg(handshake, "wrong type of proposal_map\n");
		goto out_free_proposal_map;
	}
	ctf_msg(handshake, "about to check proposal map length\n");
	if (!len) {
		ctf_msg(handshake, "zero length proposal_map\n");
		goto out_free_proposal_map;
	}
	ctf_msg(handshake, "about to do proposal map loop\n");
	for (k = 0; k < len; ++k) {
		struct cbor_pair pair;
		uintmax_t key, value;

		ctf_msg(handshake, "doing proposal map loop iter %u\n", k);
		/* what are these keys? */
		if (!(pair.key = cbor_build_encode_word(handshake_propose_versions[k].propose_version_key))) {
			ctf_msg(handshake, "[%u] cbor_build_encode_word() "
					   "failed!\n", k);
			goto out_free_proposal_map;
		}
		/* validity check? */
		ctf_msg(handshake, "value NULL check proposal map loop iter %u\n", k);
		if (!(pair.value = handshake_propose_versions[k].propose_version_value)) {
			ctf_msg(handshake, "handshake_propose_versions[%u] "
					   "NULL!\n", k);
			goto out_free_proposal_map;
		}
		ctf_msg(handshake, "getting value proposal map loop iter %u\n", k);
		if (!cbor_get_uint(pair.value, &value)) {
			ctf_msg(handshake, "handshake_propose_versions[%u] "
					   "CBOR uint decoding failed!\n", k);
			goto out_free_proposal_map;
		}
		key = (uintmax_t)
			handshake_propose_versions[k].propose_version_key;
		ctf_msg(handshake, "proposal map key = 0x%jx,"
				   " value = 0x%jx\n", key, value);
		ctf_msg(handshake, "adding to proposal map loop iter %u\n", k);
		if (!cbor_map_add(proposal_map, pair)) {
			ctf_msg(handshake, "cbor_map_add() of pair %u "
					   "failed!\n", k);
			goto out_free_proposal_map;
		}
		ctf_msg(handshake, "finished proposal map loop iter %u\n", k);
	}
	if (!cbor_array_set(proposal_array, 1, proposal_map)) {
		ctf_msg(handshake, "setting proposal_array[1] to "
				   "proposal_map failed!\n");
		goto out_free_proposal_map;
	}
	if (cbor_typeof(proposal_map) != CBOR_TYPE_MAP) {
		ctf_msg(handshake, "proposal_map changed type!\n");
		goto out_free_proposal_map;
	}
	cbor_describe(proposal_array, stderr);
	fflush(stderr);
	return proposal_array;
out_free_proposal_map:
	ctf_msg(handshake, "out_free_proposal_map "
			   "propose_versions_encode() goto label\n");
	ctf_cbor_decref(handshake, &proposal_map);
out_free_array_zero_element:
	ctf_msg(handshake, "out_free_array_zero_element "
			   "propose_versions_encode() goto label\n");
	ctf_cbor_decref(handshake, &array_zero_element);
out_free_proposal_array:
	ctf_msg(handshake, "out_free_proposal_array "
			   "propose_versions_encode() goto label\n");
	ctf_cbor_decref(handshake, &proposal_array);
	ctf_msg(handshake, "propose_versions_encode() failure return!\n");
	return NULL;
}

#if defined(PROPOSE_VERSIONS_ENCODE_BAD)
static cbor_item_t *
propose_versions_encode_bad(const struct handshake_propose_versions *propose_versions)
{
	cbor_item_t *type_tag, *versions_len, *versions_map,
		    *versions_array, *item, *len;
	unsigned k;

	if (!(item = cbor_new_definite_array(3)))
		return NULL;
	if (!(len = cbor_build_encode_word(3)))
		goto exit_free_item;
	if (!cbor_array_set(item, 0, len))
		goto exit_free_len;
	if (!(type_tag = cbor_build_encode_word(handshake_propose_versions)))
		goto exit_free_len;
	if (!cbor_array_set(item, 1, type_tag))
		goto exit_free_tag;
	if (!(versions_array = cbor_new_definite_array(propose_versions->handshake_propose_versions_len+1)))
		goto exit_free_tag;
	if (!cbor_array_set(item, 1, versions_array))
		goto exit_free_map;
	versions_len = cbor_build_encode_word(propose_versions->handshake_propose_versions_len);
	if (!versions_len)
		goto exit_free_map;
	if (!cbor_array_set(versions_map, 0, versions_len))
		goto exit_free_map_len;
	for (k = 1; k < propose_versions->handshake_propose_versions_len; ++k) {
		struct cbor_pair pair;
		struct handshake_propose_version_pair *elem;

		elem = &propose_versions->handshake_propose_versions[k];
		pair.key = cbor_build_encode_word(elem->propose_version_key);
		if (!pair.key)
			goto exit_free_map_len;
		pair.value = elem->propose_version_value;
		if (!cbor_map_add(versions_map, pair)) {
			ctf_cbor_decref(handshake, &pair.key);
			goto exit_free_map_len;
		}
	}
	return item;
exit_free_map_len:
	ctf_cbor_decref(handshake, &versions_len);
exit_free_map:
	ctf_cbor_decref(handshake, &versions_map);
exit_free_tag:
	ctf_cbor_decref(handshake, &type_tag);
exit_free_len:
	ctf_cbor_decref(handshake, &len);
exit_free_item:
	ctf_cbor_decref(handshake, &item);
	return NULL;
}
#endif

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
	cbor_item_t *retval = NULL;
	ctf_msg(handshake, "entering handshake_encode()\n");
	/* fprintf(stderr, "entering handshake_encode()\n");
	exit(EXIT_FAILURE); */
	switch (handshake->handshake_type) {
	case handshake_propose_versions:
		ctf_msg(handshake, "calling propose_versions_encode()\n");
		fprintf(stderr, "calling propose_versions_encode()\n");
		retval = propose_versions_encode(&handshake->handshake_message.propose_versions);
		break;
	case handshake_accept_version:
		ctf_msg(handshake, "calling accept_version_encode()\n");
		fprintf(stderr, "calling accept_version_encode()\n");
		retval = accept_version_encode(&handshake->handshake_message.accept_version);
		break;
	case handshake_refusal:
		ctf_msg(handshake, "calling refusal_encode()\n");
		fprintf(stderr, "calling refusal_encode()\n");
		retval = refusal_encode(&handshake->handshake_message.refusal);
		break;
	case handshake_query_reply:
		ctf_msg(handshake, "calling query_reply_encode()\n");
		fprintf(stderr, "calling query_reply_encode()\n");
		retval = query_reply_encode(&handshake->handshake_message.query_reply);
		break;
	default:
		ctf_msg(handshake, "unrecognized handshake_type %d\n",
				(int)handshake->handshake_type);
		break;
	}
	return retval;
}
