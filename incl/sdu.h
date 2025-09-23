#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "mpn.h"

/* this needs conversion to big-endian to serve as a header */
struct sdu {
	/* RemoteClockModel wraps Word32 */
	uint32_t sdu_xmit;
	/* Raw second 32-bit chunk */
	uint32_t sdu_chunk2;
	/* MiniProtocolNum wraps Word16 */
	union {
		enum mini_protocol_num sdu_proto_num;
		uint16_t sdu_proto_word16;
	} sdu_proto_un;
	/* mhLength of SDUHeader is Word16 */
	uint16_t sdu_len;
	/* MiniProtocolDir is a 2-case variant both 0-adic */
	bool sdu_init_or_resp;
	/* end of msHeader :: SDUHeader, now msBlob :: ByteString */
	const char *sdu_data;
} __attribute__((packed,aligned(8)));

union sdu_ptr {
	uint32_t *sdu32;
	uint16_t *sdu16;
	uint8_t  *sdu8;
} __attribute__((packed,aligned(8)));

int sdu_encode(const struct sdu *, union sdu_ptr);
int sdu_decode(const union sdu_ptr, struct sdu *);
int sdu_print(const struct sdu *);
