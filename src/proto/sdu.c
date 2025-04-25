#include <inttypes.h>
#include <stdio.h>
#include "sdu.h"
#include "c_trace_fwd.h"

int
sdu_decode(const uint32_t hdr[2], struct sdu *sdu)
{
	uint32_t tmp = ntohl(hdr[1]);

	sdu->sdu_xmit = ntohl(hdr[0]);
	sdu->sdu_init_or_resp = !!(tmp & 1UL);
	sdu->sdu_proto_num = (tmp >> 1) & ((1U << 15) - 1);
	sdu->sdu_len = tmp >> 16;
	/*
	 * It may look tempting to do something akin to:
	 * sdu->sdu_data = (const char *)&hdr[2];
	 * however, this has the significant issue that it can very
	 * much make sense to maintain a fixed-size buffer for the SDU
	 * headers and then to dynamically size the CBOR buffers
	 * according to the header's payload length field.
	 */
	return RETVAL_SUCCESS;
}

int
sdu_encode(const struct sdu *sdu, uint32_t hdr [2])
{
	hdr[0] = htonl(sdu->sdu_xmit);
	hdr[1] = htons(sdu->sdu_proto_num)
		| (sdu->sdu_init_or_resp ? 0 : 1U << 15)
		| (uint32_t)htons(sdu->sdu_len) << 16;
	return RETVAL_SUCCESS;
}

int
sdu_print(const struct sdu *sdu)
{
	printf(	"struct sdu {\n");
	printf(	"	uint32_t sdu_xmit = 0x%"PRIx32";\n",
		sdu->sdu_xmit);
	printf(	"	uint16_t sdu_proto_num = %"PRIu16
		                             " (0x%"PRIx16");\n",
		sdu->sdu_proto_num,
		sdu->sdu_proto_num);
	printf(	"	uint16_t sdu_len = %"PRIu16
		                       " (0x%"PRIx16");\n",
		sdu->sdu_len,
		sdu->sdu_len);
	printf(	"	bool sdu_init_or_resp = %s;\n",
		sdu->sdu_init_or_resp ? "true" : "false");
	printf(	"	const char *sdu_data = %p; };\n",
		sdu->sdu_data);
	return RETVAL_SUCCESS;
}
