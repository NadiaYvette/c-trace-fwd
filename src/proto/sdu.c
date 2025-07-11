#include <inttypes.h>
#include <stdio.h>
#include "sdu.h"
#include "c_trace_fwd.h"

int
sdu_decode(const uint32_t hdr[2], struct sdu *sdu)
{
	uint16_t non_timestamp_network_words[2];

	non_timestamp_network_words[0]
		= hdr[1] & ((((uint32_t)1UL) << 16) - 1);
	non_timestamp_network_words[1]
		= (hdr[1] >> 16) & ((((uint32_t)1UL) << 16) - 1);
	sdu->sdu_xmit = ntohl(hdr[0]);
	sdu->sdu_chunk2 = ntohl(hdr[1]);
	sdu->sdu_init_or_resp = !!(non_timestamp_network_words[0] & 1UL);
	sdu->sdu_proto_un.sdu_proto_num
		= ntohs(non_timestamp_network_words[0] >> 1);
	sdu->sdu_len = ntohs(non_timestamp_network_words[1]);
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
	uint16_t non_timestamp_network_words[2];

	non_timestamp_network_words[0]
		= (htons(sdu->sdu_proto_un.sdu_proto_word16) << 1)
		| (sdu->sdu_init_or_resp ? 1UL : 0UL);
	non_timestamp_network_words[1] = htons(sdu->sdu_len);
	hdr[0] = htonl(sdu->sdu_xmit);
	hdr[1] = non_timestamp_network_words[0]
		| (uint32_t)non_timestamp_network_words[1] << 16;
	/* assert(hdr[1] == sdu->sdu_chunk2); */
	return RETVAL_SUCCESS;
}

int
sdu_print(const struct sdu *sdu)
{
	printf(	"struct sdu {\n");
	printf(	"	uint32_t sdu_xmit = 0x%"PRIx32";\n",
		sdu->sdu_xmit);
	printf(	"	uint32_t sdu_chunk2 = 0x%"PRIx32" (host) "
					     "0x%"PRIx32" (network);\n",
		sdu->sdu_chunk2,
		htonl(sdu->sdu_chunk2));
	printf(	"	uint16_t sdu_proto_num = %"PRIu16
		                             " (0x%"PRIx16");\n",
		sdu->sdu_proto_un.sdu_proto_word16,
		sdu->sdu_proto_un.sdu_proto_word16);
	printf(	"	uint16_t sdu_len = %"PRIu16
		                       " (0x%"PRIx16");\n",
		sdu->sdu_len,
		sdu->sdu_len);
	printf(	"	bool sdu_init_or_resp = %s;\n",
		sdu->sdu_init_or_resp ? "InitiatorDir" : "ResponderDir");
	printf(	"	const char *sdu_data = %p; };\n",
		sdu->sdu_data);
	return RETVAL_SUCCESS;
}
