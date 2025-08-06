#pragma once

#include <cbor.h>
#include "handshake.h"
#include "sdu.h"
#include "tof.h"

struct ctf_proto_stk_decode_result {
	struct cbor_load_result load_result;
	struct sdu sdu;
	union {
		cbor_item_t *undecoded;
		struct tof_msg *tof_msg;
		struct handshake *handshake_msg;
	} proto_stk_decode_result_body;
};

struct ctf_proto_stk_decode_result *ctf_proto_stk_decode(const void *);
void *ctf_proto_stk_encode(const struct tof_msg *, size_t *);
void cpsdr_free(struct ctf_proto_stk_decode_result *);
