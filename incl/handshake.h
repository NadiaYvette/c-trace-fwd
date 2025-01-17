#pragma once

#include <cbor.h>
#include <stdint.h>

/*
 * nodeToClientVersionCodec
 * :: CodecCBORTerm (Text, Maybe Int) NodeToClientVersion
 */

struct handshake_propose_version_pair {
	uint16_t propose_version_key;
	cbor_item_t *propose_version_value;
};

struct handshake_propose_versions {
	int handshake_propose_versions_len;
	struct handshake_propose_version_pair *handshake_propose_versions;
};

/* struct handshake_reply_versions; */

struct handshake_accept_version {
	/* the CBOR just wraps a number AFAICT */
	uint16_t handshake_accept_version_number;
	/* interpreting it more deeply than CBOR.Term is difficult */
	cbor_item_t *handshake_accept_version_params;
};

enum handshake_refusal_reason_type {
	handshake_refusal_version_mismatch = 0,
	handshake_refusal_decode_error = 1,
	handshake_refusal_refused = 2
};

struct handshake_refusal_version_mismatch {
	int handshake_refusal_version_mismatch_len;
	uint16_t *handshake_refusal_version_mismatch_versions;
};

struct handshake_refusal_decode_error {
	uint16_t handshake_refusal_decode_error_version;
	char *handshake_refusal_decode_error_string;
};

struct handshake_refusal_refused {
	uint16_t handshake_refusal_refused_version;
	char *handshake_refusal_refused_string;
};

union handshake_refusal_message {
	struct handshake_refusal_version_mismatch version_mismatch;
	struct handshake_refusal_decode_error decode_error;
	struct handshake_refusal_refused refused;
};

struct handshake_refusal {
	enum handshake_refusal_reason_type reason_type;
	union handshake_refusal_message refusal_message;
};

/* struct handshake_query_reply; */

enum handshake_type {
	handshake_propose_versions = 0,
	handshake_accept_version = 1,
	handshake_refusal = 2
	/* handshake_query_reply = 3 */
};

struct handshake {
	enum handshake_type handshake_type;
	union {
		struct handshake_propose_versions propose_versions;
		/* struct handshake_reply_versions reply_versions; */
		/* struct handshake_query_reply query_reply; */
		struct handshake_accept_version accept_version;
		struct handshake_refusal refusal;
	} handshake_message;
};

struct handshake *handshake_decode(const cbor_item_t *);
cbor_item_t *handshake_encode(const struct handshake *);
