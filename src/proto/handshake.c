#include <cbor.h>
#include <cbor/ints.h>
#include <glib.h>
#include <limits.h>
#include <linux/errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "handshake.h"
#include "sdu.h"
#include "tof.h"

const char *
handshake_string(enum handshake_type handshake_type)
{
	static const char *handshake_type_table[] = {
		[handshake_propose_versions] = "handshake_propose_versions",
		[handshake_accept_version] = "handshake_accept_version",
		[handshake_refusal] = "handshake_refusal",
		[handshake_query_reply] = "handshake_query_reply",
	};
	if (!HANDSHAKE_TYPE_VALID(handshake_type))
		return NULL;
	return handshake_type_table[handshake_type];
}

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
		ctf_msg(ctf_alert, handshake, "item %d not UINT\n",
				cbor_typeof(item));
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
		ctf_msg(ctf_alert, handshake, "unrecognized uint width\n");
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
		= g_rc_box_alloc0(propose_versions->handshake_propose_versions_len * sizeof(struct handshake_propose_version_pair));
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
		= g_rc_box_alloc0(mismatch->handshake_refusal_version_mismatch_len * sizeof(uint64_t));
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
	cbor_item_t *item;
	const char **string;
	uintmax_t value;

	refusal = &handshake->handshake_message.refusal;
	refused = &refusal->refusal_message.refused;
	string  = (const char **)&refused->handshake_refusal_refused_string;
	if (!(item = cbor_array_get(refusal_array, 1)))
		return NULL;
	/* The versions must be non-negative. */
	if (!cbor_isa_uint(item))
		goto out_decref;
	if (!cbor_get_uint(item, &value))
		goto out_decref;
	refused->handshake_refusal_refused_version = (uint64_t)value;
	if (!cbor_strdup_array_get(string, refusal_array, 2))
		goto out_decref;
	return handshake;
out_decref:
	cbor_decref(&item);
	return NULL;
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
		= g_rc_box_alloc0(query_reply->handshake_query_reply_len * sizeof(struct handshake_query_reply_pair));
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

	if (!(handshake = g_rc_box_new0(struct handshake)))
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
	handshake_free(handshake);
	return NULL;
}

static void
handshake_release_memory(void *p)
{
	struct handshake *handshake = p;
	union handshake_message *msg = &handshake->handshake_message;

	switch (handshake->handshake_type) {
	case handshake_propose_versions:
		struct handshake_propose_versions *hpv;

		hpv = &msg->propose_versions;
		g_rc_box_release(hpv->handshake_propose_versions);
		break;
	case handshake_accept_version:
		struct handshake_accept_version *hav;

		hav = &msg->accept_version;
		ctf_cbor_decref(handshake, &hav->handshake_accept_version_params);
		break;
	case handshake_query_reply:
		struct handshake_query_reply *hqr = &msg->query_reply;
		unsigned k;

		for (k = 0; k < hqr->handshake_query_reply_len; ++k)
			cbor_decref(&hqr->handshake_query_reply[k].query_reply_value);
		break;
	case handshake_refusal:
		struct handshake_refusal *hr = &msg->refusal;

		switch (hr->reason_type) {
		case handshake_refusal_version_mismatch:
			g_rc_box_release(hr->refusal_message.version_mismatch.handshake_refusal_version_mismatch_versions);
			break;
		case handshake_refusal_decode_error:
			g_rc_box_release(hr->refusal_message.decode_error.handshake_refusal_decode_error_string);
			break;
		case handshake_refusal_refused:
			g_rc_box_release(hr->refusal_message.refused.handshake_refusal_refused_string);
			break;
		default:
			ctf_msg(ctf_alert, handshake,
					"unrecognized handshake refusal\n");
		}
		break;
	default:
		ctf_msg(ctf_alert, handshake,
				"freeing handshake of unrecognized type\n");
	}
}

void
handshake_free(struct handshake *handshake)
{
	g_rc_box_release_full(handshake, handshake_release_memory);
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
	ctf_cbor_decref(handshake, &array_zero_element);
	ctf_msg(ctf_debug, handshake, "about to build proposal map\n");
	if (!(proposal_map = cbor_new_definite_map(propose_versions->handshake_propose_versions_len))) {
		ctf_msg(ctf_debug, handshake,
			"allocation of proposal "
			"map of length %zd failed!\n",
			propose_versions->handshake_propose_versions_len);
		goto out_free_array_zero_element;
	}
	ctf_msg(ctf_debug, handshake, "about to check proposal map type\n");
	if (cbor_typeof(proposal_map) != CBOR_TYPE_MAP) {
		ctf_msg(ctf_debug, handshake, "wrong type of proposal_map\n");
		goto out_free_proposal_map;
	}
	ctf_msg(ctf_debug, handshake, "about to check proposal map length\n");
	if (!len) {
		ctf_msg(ctf_alert, handshake, "zero length proposal_map\n");
		goto out_free_proposal_map;
	}
	ctf_msg(ctf_debug, handshake, "about to do proposal map loop\n");
	for (k = 0; k < len; ++k) {
		struct cbor_pair pair;
		uintmax_t key, value;

		ctf_msg(ctf_debug, handshake,
				"doing proposal map loop iter %u\n", k);
		/* what are these keys? */
		if (!(pair.key = cbor_build_encode_word(handshake_propose_versions[k].propose_version_key))) {
			ctf_msg(ctf_alert, handshake,
					"[%u] cbor_build_encode_word() "
					"failed!\n", k);
			goto out_free_proposal_map;
		}
		/* validity check? */
		ctf_msg(ctf_debug, handshake,
				"value NULL check proposal "
				"map loop iter %u\n", k);
		if (!(pair.value = handshake_propose_versions[k].propose_version_value)) {
			ctf_msg(ctf_alert, handshake,
					"handshake_propose_versions[%u] "
					"NULL!\n", k);
			goto out_free_proposal_map;
		}
		ctf_msg(ctf_debug, handshake,
				"getting value proposal map "
				"loop iter %u\n", k);
		if (!cbor_get_uint(pair.value, &value)) {
			ctf_msg(ctf_alert, handshake,
					"handshake_propose_versions[%u] "
					"CBOR uint decoding failed!\n", k);
			goto out_free_proposal_map;
		}
		key = (uintmax_t)
			handshake_propose_versions[k].propose_version_key;
		ctf_msg(ctf_debug, handshake, "proposal map key = 0x%jx,"
				   " value = 0x%jx\n", key, value);
		ctf_msg(ctf_debug, handshake,
				"adding to proposal map loop iter %u\n", k);
		if (!cbor_map_add(proposal_map, pair)) {
			ctf_msg(ctf_alert, handshake,
					"cbor_map_add() of pair %u "
					"failed!\n", k);
			goto out_free_proposal_map;
		}
		ctf_cbor_decref(handshake, &pair.key);
		ctf_msg(ctf_debug, handshake,
				"finished proposal map loop iter %u\n", k);
	}
	if (!cbor_array_set(proposal_array, 1, proposal_map)) {
		ctf_msg(ctf_alert, handshake, "setting proposal_array[1] to "
				   "proposal_map failed!\n");
		goto out_free_proposal_map;
	}
	ctf_cbor_decref(handshake, &proposal_map);
	if (cbor_typeof(proposal_map) != CBOR_TYPE_MAP) {
		ctf_msg(ctf_alert, handshake, "proposal_map changed type!\n");
		goto out_free_proposal_map;
	}
	cbor_describe(proposal_array, stderr);
	fflush(stderr);
	return proposal_array;
out_free_proposal_map:
	ctf_msg(ctf_debug, handshake, "out_free_proposal_map "
			   "propose_versions_encode() goto label\n");
	ctf_cbor_decref(handshake, &proposal_map);
out_free_array_zero_element:
	ctf_msg(ctf_debug, handshake, "out_free_array_zero_element "
			   "propose_versions_encode() goto label\n");
	ctf_cbor_decref(handshake, &array_zero_element);
out_free_proposal_array:
	ctf_msg(ctf_debug, handshake, "out_free_proposal_array "
			   "propose_versions_encode() goto label\n");
	ctf_cbor_decref(handshake, &proposal_array);
	ctf_msg(ctf_debug, handshake,
			"propose_versions_encode() failure return!\n");
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
	cbor_item_t *item, *tmp;

	if (!(item = cbor_new_definite_array(3)))
		return NULL;

	if (!(tmp = cbor_build_encode_word(handshake_accept_version)))
		goto out_free_item;
	if (!cbor_array_set(item, 0, tmp)) {
		ctf_cbor_decref(handshake, &tmp);
		goto out_free_item;
	}
	ctf_cbor_decref(handshake, &tmp);

	if (!(tmp = cbor_build_encode_word(accept_version->handshake_accept_version_number)))
		goto out_free_item;
	if (!cbor_array_set(item, 1, tmp)) {
		ctf_cbor_decref(handshake, &tmp);
		goto out_free_item;
	}
	ctf_cbor_decref(handshake, &tmp);

	if (!cbor_array_set(item, 2, accept_version->handshake_accept_version_params))
		goto out_free_item;
	return item;
out_free_item:
	ctf_cbor_decref(handshake, &item);
	return NULL;
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
	ctf_msg(ctf_debug, handshake, "entering handshake_encode()\n");
	switch (handshake->handshake_type) {
	case handshake_propose_versions:
		ctf_msg(ctf_debug, handshake,
				"calling propose_versions_encode()\n");
		retval = propose_versions_encode(&handshake->handshake_message.propose_versions);
		break;
	case handshake_accept_version:
		ctf_msg(ctf_debug, handshake,
				"calling accept_version_encode()\n");
		retval = accept_version_encode(&handshake->handshake_message.accept_version);
		break;
	case handshake_refusal:
		ctf_msg(ctf_debug, handshake, "calling refusal_encode()\n");
		retval = refusal_encode(&handshake->handshake_message.refusal);
		break;
	case handshake_query_reply:
		ctf_msg(ctf_debug, handshake, "calling query_reply_encode()\n");
		fprintf(stderr, "calling query_reply_encode()\n");
		retval = query_reply_encode(&handshake->handshake_message.query_reply);
		break;
	default:
		ctf_msg(ctf_alert, handshake,
				"unrecognized handshake_type %d\n",
				(int)handshake->handshake_type);
		break;
	}
	return retval;
}

static struct handshake_propose_version_pair handshake_versions[] = {
	[0] = {
		.propose_version_key = 1, /* 19, */
		.propose_version_value = NULL
	}
};

static struct handshake handshake_proposal = {
	.handshake_type = handshake_propose_versions,
	.handshake_message = {
		.propose_versions = {
			.handshake_propose_versions_len = 1,
			.handshake_propose_versions = handshake_versions
		}
	}
};

static cbor_item_t *handshake_proposal_cbor = NULL;

int
handshake_xmit(int fd)
{
	struct handshake *handshake_reply;
	cbor_item_t *reply_cbor, *handshake_proposal_map;
	unsigned char *sdu_buf, *buf = NULL, sdu_bytearray[8];
	size_t buf_sz, sdu_buf_sz, send_len;
	ssize_t reply_len, send_ret;
	int retval = RETVAL_FAILURE;
	struct sdu sdu, reply_sdu;
	struct cbor_load_result cbor_load_result;
	union sdu_ptr sdu_ptr;
	struct pollfd pollfd = {
		.fd = fd,
		.events = POLLOUT,
		.revents = 0,
	};

	ctf_msg(ctf_debug, handshake, "entering\n");
	ctf_msg(ctf_debug, handshake, "different message\n");
	handshake_versions[0].propose_version_key = 1;
	if (!handshake_versions[0].propose_version_value) {
		handshake_versions[0].propose_version_value
			= cbor_build_uint32( 764824073 /* 19 */ );
		if (!handshake_versions[0].propose_version_value) {
			ctf_msg(ctf_alert, handshake,
					"version value alloc failed\n");
			return RETVAL_FAILURE;
		}
	}
	ctf_msg(ctf_debug, handshake,
			"past checking version value, "
			"about to cbor encode\n");
	if (!(handshake_proposal_cbor = handshake_encode(&handshake_proposal))) {
		ctf_msg(ctf_debug, handshake,
				"handshake_encode() returned "
				"NULL & failed!\n");
		return RETVAL_FAILURE;
	}
	ctf_msg(ctf_debug, handshake, "handshake_encode() succeeded\n");
	cbor_describe(handshake_proposal_cbor, stderr);
	if (!cbor_serialize_alloc(handshake_proposal_cbor, &buf, &buf_sz)) {
		ctf_msg(ctf_alert, handshake,
				"cbor_serialize_alloc failed\n");
		return RETVAL_FAILURE;
	}
	if (cbor_typeof(handshake_proposal_cbor) != CBOR_TYPE_ARRAY) {
		ctf_msg(ctf_alert, handshake,
				"handshake_encode() didn't return array!\n");
		return RETVAL_FAILURE;
	}
	if (cbor_array_size(handshake_proposal_cbor) != 2) {
		ctf_msg(ctf_alert, handshake,
				"handshake_encode() returned "
				"wrong size array!\n");
		return RETVAL_FAILURE;
	}
	if (!(handshake_proposal_map = cbor_array_get(handshake_proposal_cbor, 1))) {
		ctf_msg(ctf_alert, handshake,
				"handshake_encode() lacked "
				"[1] array entry!\n");
		return RETVAL_FAILURE;

	}
	if (cbor_typeof(handshake_proposal_map) != CBOR_TYPE_MAP) {
		ctf_msg(ctf_alert, handshake,
				"handshake_encode() [1] array entry "
				"not CBOR_TYPE_MAP!\n");
		return RETVAL_FAILURE;
	}
	sdu_buf_sz = buf_sz + 2*sizeof(uint32_t);
	if (!(sdu_buf = calloc(sdu_buf_sz, sizeof(unsigned char)))) {
		ctf_msg(ctf_alert, handshake, "sdu_buf calloc failed\n");
		goto out_free_buf;
	}
	sdu.sdu_xmit = (uint32_t)time(NULL);
	sdu.sdu_init_or_resp = CTF_INIT_OR_RESP;
	/* sdu.sdu_proto_un.sdu_proto_word16 = 19; */
	sdu.sdu_proto_un.sdu_proto_num = mpn_handshake;
	sdu.sdu_len = buf_sz;
	sdu.sdu_data = (char *)&sdu_buf[sizeof(struct sdu)];
	memcpy(&sdu_buf[2*sizeof(uint32_t)], buf, buf_sz);
	sdu_ptr.sdu8 = (uint8_t *)sdu_buf;
	if (sdu_encode(&sdu, sdu_ptr) != RETVAL_SUCCESS) {
		ctf_msg(ctf_alert, handshake, "sdu_encode failed\n");
		goto out_free_sdu;
	}
	send_len = buf_sz + 2*sizeof(uint32_t);
	(void)!poll(&pollfd, 1, -1);
	if ((send_ret = write(fd, sdu_buf, send_len)) <= 0 && errno != 0) {
		ctf_msg(ctf_alert, handshake,
				"write error in handshake\n");
		ctf_msg(ctf_debug, handshake,
				"write(%d, %p, %zd) = %zd, "
				"errno=%d (%s)\n",
				fd, sdu_buf, send_len,
				send_ret, errno, strerror(errno));
		goto out_free_buf;
	}
	if (buf_sz < 64 * 1024) {
		unsigned char *new_buf;

		ctf_msg(ctf_debug, handshake, "reallocating buffer\n");
		if (!(new_buf = realloc(buf, 64 * 1024)))
			goto out_free_buf;
		buf_sz = 64 * 1024;
		buf = new_buf;
		ctf_msg(ctf_debug, handshake,
				"buffer successfully reallocated\n");
	}
	ctf_msg(ctf_debug, handshake,
			"about to try to read for handshake reply\n");
	if ((reply_len = read(fd, sdu_bytearray, 8)) != 8) {
		ctf_msg(ctf_debug, handshake, "handshake reply SDU read fail\n");
		goto out_free_buf;
	}
	ctf_msg(ctf_debug, handshake, "attempting sdu_decode()\n");
	sdu_ptr.sdu8 = (uint8_t *)sdu_bytearray;
	if (sdu_decode(sdu_ptr, &reply_sdu) != RETVAL_SUCCESS) {
		ctf_msg(ctf_alert, handshake,
				"saw sdu_decode() failure, now goto "
				"out_free_buf\n");
		goto out_free_buf;
	}
	ctf_msg(ctf_debug, handshake, "got past sdu_decode(), "
			"checking reply_sdu.sdu_len\n");
	if (false && reply_sdu.sdu_len != reply_len - 2 * sizeof(uint32_t)) {
		ctf_msg(ctf_alert, handshake,
				"SDU length unexpected was 0x%x expected"
			       " 0x%zx\n", reply_sdu.sdu_len,
			       (size_t)reply_len);
		reply_sdu.sdu_len = reply_len - 2*sizeof(uint32_t);
	}
	ctf_msg(ctf_debug, handshake,
			"got past reply_sdu.sdu_len check "
			"trying cbor_load()\n");
	while ((reply_len = read(fd, buf, reply_sdu.sdu_len)) <= 0) {
		if (!errno_is_restart(errno)) {
			ctf_msg(ctf_alert, handshake,
					"handshake read got "
					"errno %d\n", errno);
			goto out_free_buf;
		}
		errno = 0;
		ctf_msg(ctf_debug, handshake, "read zero data, looping\n");
	}
	if (!errno)
		ctf_msg(ctf_debug, handshake,
				"got past reading for handshake reply\n");
	else
		ctf_msg(ctf_alert, handshake,
				"error reading for handshake reply\n");
	if (reply_len < 0) {
		ctf_msg(ctf_alert, handshake,
				"negative reply length, exiting\n");
		goto out_free_buf;
	}
	if (!(reply_cbor = cbor_load(&buf[0], reply_sdu.sdu_len, &cbor_load_result))) {
		ctf_msg(ctf_alert, handshake,
				"cbor_load() failed, freeing buffer\n");
		goto out_free_buf;
	}
	ctf_msg(ctf_debug, handshake,
			"got past cbor_load(), checking result\n");
	switch (cbor_load_result.error.code) {
	case CBOR_ERR_NONE:
		ctf_msg(ctf_debug, handshake,
				"got CBOR_ERR_NONE, continuing\n");
		break;
	case CBOR_ERR_NOTENOUGHDATA:
		ctf_msg(ctf_alert, handshake, "got CBOR_ERR_NOTENOUGHDATA\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_NODATA:
		ctf_msg(ctf_alert, handshake, "got CBOR_ERR_NODATA\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_MALFORMATED:
		ctf_msg(ctf_alert, handshake, "got CBOR_ERR_MALFORMATED\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_MEMERROR:
		ctf_msg(ctf_alert, handshake, "got CBOR_ERR_MEMERROR\n");
		goto out_decref_reply;
		break;
	case CBOR_ERR_SYNTAXERROR:
		ctf_msg(ctf_alert, handshake, "got CBOR_ERR_SYNTAXERROR\n");
		goto out_decref_reply;
		break;
	default:
		ctf_msg(ctf_alert, handshake,
				"got unrecognized CBOR error code\n");
		goto out_decref_reply;
		break;
	}
	ctf_msg(ctf_debug, handshake,
			"got past checking cbor_load() result, "
		       "doing handshake_decode()\n");
	if (!(handshake_reply = handshake_decode(reply_cbor))) {
		ctf_msg(ctf_alert, handshake,
				"handshake_decode() failed "
				"decref(&reply_cbor)\n");
		goto out_decref_reply;
	}
	ctf_msg(ctf_debug, handshake,
			"got past handshake_decode(), "
			"checking reply type\n");
	if (handshake_reply->handshake_type != handshake_accept_version) {
		ctf_msg(ctf_warning, handshake,
				"reply type not acceptance, "
				"decref(&reply_cbor)\n");
		goto out_handshake_free;
	}
	ctf_msg(ctf_debug, handshake,
			"handshake_xmit() succeeded, "
			"returning RETVAL_SUCCESS\n");
	retval = RETVAL_SUCCESS;
out_handshake_free:
	handshake_free(handshake_reply);
out_decref_reply:
	if (!!retval)
		ctf_msg(ctf_debug, handshake,
				"out_decref_reply: label "
				"of handshake_xmit()\n");
	ctf_cbor_decref(state, &reply_cbor);
out_free_sdu:
	if (!!retval)
		ctf_msg(ctf_debug, handshake, "out_free_sdu: label "
				"of handshake_xmit()\n");
	free(sdu_buf);
out_free_buf:
	if (!!retval)
		ctf_msg(ctf_debug, handshake, "out_free_buf: label "
				"of handshake_xmit()\n");
	free(buf);
	return retval;
}
