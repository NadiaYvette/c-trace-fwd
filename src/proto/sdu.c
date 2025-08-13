#include <endian.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "sdu.h"

const char *
agency_string(enum agency agency)
{
	static const char *agency_table[] = {
		[agency_local]  = "agency_local",
		[agency_nobody] = "agency_nobody",
		[agency_remote] = "agency_remote",
	};

	if (AGENCY_VALID(agency))
		return agency_table[agency];
	return NULL;
}

const char *
mini_protocol_string(enum mini_protocol_num mpn)
{
	static char *mpn_string_table[9] = {
		[mpn_handshake]        = "mpn_handshake",
		[mpn_EKG_metrics]      = "mpn_EKG_metrics",
		[mpn_trace_objects]    = "mpn_trace_objects",
		[mpn_data_points]      = "mpn_data_points",
		[mpn_node_tx_submit]   = "mpn_node_tx_submit",
		[mpn_chain_sync]       = "mpn_chain_sync",
		[mpn_client_tx_submit] = "mpn_client_tx_submit",
		[mpn_state_query]      = "mpn_state_query",
		[mpn_keepalive]        = "mpn_keepalive",
	};

	return MPN_VALID(mpn) ? mpn_string_table[mpn] : NULL;
}

int
sdu_decode(const union sdu_ptr hdr, struct sdu *sdu)
{
	sdu->sdu_xmit = be32toh(hdr.sdu32[0]);
	sdu->sdu_xmit
		= (uint32_t)hdr.sdu8[0] << (3*8)
		| (uint32_t)hdr.sdu8[1] << (2*8)
		| (uint32_t)hdr.sdu8[2] << (1*8)
		| (uint32_t)hdr.sdu8[3] << (0*8);
	if (sdu->sdu_xmit != be32toh(hdr.sdu32[0])) {
		ctf_msg(sdu, "->sdu_xmit failed to reassemble!\n");
		ctf_msg(sdu, "->sdu_xmit = 0x%"PRIx32"\n", sdu->sdu_xmit);
		ctf_msg(sdu, "be32toh(hdr.sdu32[0]) = 0x%"PRIx32"\n",
			       be32toh(hdr.sdu32[0]));
		for (unsigned k = 0; k < 4; ++k) {
			ctf_msg(sdu, "hdr.sdu8[%u] (n) = 0x%"PRIx8"\n", k, hdr.sdu8[k]);
		}
	}
	sdu->sdu_chunk2 = be32toh(hdr.sdu32[1]);
	sdu->sdu_init_or_resp
		= !!(be16toh(hdr.sdu16[2]) & 0x8000U);
	sdu->sdu_proto_un.sdu_proto_num
		= ( (uint16_t)hdr.sdu8[4+0] << (1*8)
		  | (uint16_t)hdr.sdu8[4+1] << (0*8)) & ~0x8000U;
	/* BE bytes decrease in numerical significance within a word.
	 * It's not clear which notion of a word is used where. */
	sdu->sdu_len
		= (uint16_t)hdr.sdu8[4+2] << (1*8)
		| (uint16_t)hdr.sdu8[4+3] << (0*8);
	if (0) {
		ctf_msg(sdu, "sdu->sdu_len = 0x%"PRIx16"\n", sdu->sdu_len);
		ctf_msg(sdu, "hdr.sdu16[3] = 0x%"PRIx16"\n", hdr.sdu16[3]);
		ctf_msg(sdu, "hdr.sdu8[6]  = 0x%"PRIx8"\n",  hdr.sdu8[6]);
		ctf_msg(sdu, "hdr.sdu8[7]  = 0x%"PRIx8"\n",  hdr.sdu8[7]);
	}
	/*
	 * It may look tempting to do something akin to:
	 * sdu->sdu_data = (const char *)&hdr.sdu8[0];
	 * however, this has the significant issue that it can very
	 * much make sense to maintain a fixed-size buffer for the SDU
	 * headers and then to dynamically size the CBOR buffers
	 * according to the header's payload length field.
	 */
	if (MPN_VALID(sdu->sdu_proto_un.sdu_proto_num)) {
		ctf_msg(sdu, "->sdu_proto_num = %s 0x%"
			PRIx16"\n",
			mini_protocol_string(sdu->sdu_proto_un.sdu_proto_num),
			sdu->sdu_proto_un.sdu_proto_word16);
		return RETVAL_SUCCESS;
	} else {
		ctf_msg(sdu, "unrecognized SDU mini_protocol_num 0x%"
				PRIx16" decoded\n",
				sdu->sdu_proto_un.sdu_proto_word16);
		ctf_msg(sdu, "32-bit endianness dump:\n");
		ctf_msg(sdu, "->sdu_xmit   (h) = 0x%"PRIx32"\n", sdu->sdu_xmit);
		ctf_msg(sdu, "->sdu_chunk2 (h) = 0x%"PRIx32"\n", sdu->sdu_chunk2);
		ctf_msg(sdu, "hdr.sdu32[0] (n) = 0x%"PRIx32"\n", hdr.sdu32[0]);
		ctf_msg(sdu, "hdr.sdu32[1] (n) = 0x%"PRIx32"\n", hdr.sdu32[1]);
		for (unsigned k = 0; k < 8; ++k)
			ctf_msg(sdu, "hdr.sdu8[%u] (n) = 0x%"PRIx8"\n",
					k, hdr.sdu8[k]);
		for (unsigned k = 0; k < 4; ++k) {
			ctf_msg(sdu, "hdr.sdu16[%u] (n) = 0x%"PRIx16
					"\n", k, hdr.sdu16[k]);
			ctf_msg(sdu, "hdr.sdu16[%u] (h) = 0x%"PRIx16
					"\n", k, be16toh(hdr.sdu16[k]));
		}
		return RETVAL_SUCCESS;
	}
}

int
sdu_encode(const struct sdu *sdu, union sdu_ptr hdr)
{
	hdr.sdu32[0] = htobe32(sdu->sdu_xmit);
	hdr.sdu16[2] = htobe16(((uint16_t)mpn_trace_objects << 1)
			       | (sdu->sdu_init_or_resp ? 1U : 0U));
	hdr.sdu16[3] = htobe16(sdu->sdu_len);
	hdr.sdu8[4+0] = (sdu->sdu_init_or_resp ? 0x80U : 0U)
		| (sdu->sdu_proto_un.sdu_proto_word16 >> 8);
	switch (sdu->sdu_proto_un.sdu_proto_num) {
	case mpn_handshake:
	case mpn_trace_objects:
	case mpn_EKG_metrics:
	case mpn_data_points:
		hdr.sdu8[4+1] = sdu->sdu_proto_un.sdu_proto_word16
				& ((1U << 8) - 1);
		break;
	default:
		if (sdu->sdu_proto_un.sdu_proto_word16 == 19) {
			ctf_msg(sdu, "mini_protocol_num == 19!\n");
			hdr.sdu8[4+1] = sdu->sdu_proto_un.sdu_proto_word16
					& ((1U << 8) - 1);
			break;
		}
		ctf_msg(sdu, "unrecognized mini_protocol_num!\n");
		ctf_msg(sdu, "sdu->sdu_proto_un.sdu_proto_word16 = 0x%"
				PRIx16"!\n",
				sdu->sdu_proto_un.sdu_proto_word16);
		if (0) {
			ctf_msg(sdu, "overriding with mpn_data_points "
					"because it's best not to try to "
					"interpret the data, because it will "
					"fail.\n");
			hdr.sdu8[4+1] = mpn_trace_objects;
		}
		if (sdu->sdu_proto_un.sdu_proto_word16 >= UINT8_MAX)
			ctf_msg(sdu, "mpn = 0x%"PRIx16" > UINT8_MAX!\n",
					sdu->sdu_proto_un.sdu_proto_word16);
		hdr.sdu8[4+1] = sdu->sdu_proto_un.sdu_proto_word16;
		break;
	}
	hdr.sdu8[4+2] = (sdu->sdu_len >> 8) & ((1U << 8) - 1);
	hdr.sdu8[4+3] = sdu->sdu_len & ((1U << 8) - 1);
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
