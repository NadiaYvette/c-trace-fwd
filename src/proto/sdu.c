#include "sdu.h"
#include "c_trace_fwd.h"

int sdu_decode(const uint32_t hdr[2], struct sdu *sdu)
{
	uint32_t tmp = ntohl(hdr[1]);

	sdu->sdu_xmit = ntohl(hdr[0]);
	sdu->sdu_init_or_resp = !!(tmp & 1UL);
	sdu->sdu_proto_num = (tmp >> 1) & ((1U << 15) - 1);
	sdu->sdu_len = tmp >> 16;
	return RETVAL_SUCCESS;
}

int sdu_encode(const struct sdu *sdu, uint32_t hdr [2])
{
	hdr[0] = htonl(sdu->sdu_xmit);
	hdr[1] = htons(sdu->sdu_proto_num)
		| (sdu->sdu_init_or_resp ? 0 : 1U << 15)
		| (uint32_t)htons(sdu->sdu_len) << 16;
	return RETVAL_SUCCESS;
}
