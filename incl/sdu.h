#pragma once

#include <stdbool.h>
#include <stdint.h>

enum mini_protocol_num {
	mpn_EKG_metrics = 1,
	mpn_trace_objects = 2,
	mpn_data_points = 3,
};

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
};

int sdu_encode(const struct sdu *, uint32_t [2]);
int sdu_decode(const uint32_t [2], struct sdu *);
int sdu_print(const struct sdu *);
