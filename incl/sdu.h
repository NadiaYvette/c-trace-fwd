#pragma once

#include <stdbool.h>
#include <stdint.h>

/* this needs conversion to big-endian to serve as a header */
struct sdu {
	/* RemoteClockModel wraps Word32 */
	uint32_t sdu_xmit;
	/* MiniProtocolNum wraps Word16 */
	uint16_t sdu_proto_num;
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
