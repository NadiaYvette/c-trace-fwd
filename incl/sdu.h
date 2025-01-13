#pragma once

#include <stdint.h>

/* this needs conversion to big-endian to serve as a header */
struct sdu {
	uint32_t sdu_xmit;
	uint16_t sdu_proto_num;
	uint16_t sdu_len;
	bool sdu_init_or_resp;
	const char *sdu_data;
};

int sdu_encode(const struct sdu *, uint32_t [2]);
int sdu_decode(const uint32_t [2], struct sdu *);
