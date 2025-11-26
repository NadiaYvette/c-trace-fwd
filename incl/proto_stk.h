#pragma once

#include <cbor.h>
#include "msg.h"
#include "sdu.h"

struct ctf_proto_stk_decode_result {
	struct cbor_load_result load_result;
	struct sdu sdu;
	void *buf;
	union msg *proto_stk_decode_result_body;
};

struct ctf_proto_stk_decode_result *ctf_proto_stk_decode(int);
void *ctf_proto_stk_encode(enum mini_protocol_num, const union msg *, size_t *);
void cpsdr_free(struct ctf_proto_stk_decode_result *);
