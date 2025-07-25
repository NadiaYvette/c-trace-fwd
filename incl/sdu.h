#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>

enum mini_protocol_num {
	mpn_handshake        = 0,
	mpn_EKG_metrics      = 1,
	mpn_trace_objects    = 2,
	mpn_data_points      = 3,
	mpn_node_tx_submit   = 4,
	mpn_chain_sync       = 5,
	mpn_client_tx_submit = 6,
	mpn_state_query      = 7,
	mpn_keepalive        = 8, /* also called TxMonitor */
};

#define MPN_MIN_0_to_4 MIN(MPN_MIN_0_to_2, MPN_MIN_3_to_4)
#define MPN_MAX_0_to_4 MAX(MPN_MAX_0_to_2, MPN_MAX_3_to_4)

#define MPN_MIN_0_to_2 MIN(mpn_handshake, MPN_MIN_1_to_2)
#define MPN_MAX_0_to_2 MAX(mpn_handshake, MPN_MAX_1_to_2)

#define MPN_MIN_1_to_2 MIN(mpn_EKG_metrics, mpn_trace_objects)
#define MPN_MAX_1_to_2 MAX(mpn_EKG_metrics, mpn_trace_objects)

#define MPN_MIN_3_to_4 MIN(mpn_data_points, mpn_node_tx_submit)
#define MPN_MAX_3_to_4 MAX(mpn_data_points, mpn_node_tx_submit)

#define MPN_MIN_5_to_8 MIN(MPN_MIN_5_to_6, MPN_MIN_7_to_8)
#define MPN_MAX_5_to_8 MAX(MPN_MAX_5_to_6, MPN_MAX_7_to_8)

#define MPN_MIN_5_to_6 MIN(mpn_chain_sync, mpn_client_tx_submit)
#define MPN_MAX_5_to_6 MAX(mpn_chain_sync, mpn_client_tx_submit)

#define MPN_MIN_7_to_8 MIN(mpn_state_query, mpn_keepalive)
#define MPN_MAX_7_to_8 MAX(mpn_state_query, mpn_keepalive)

#define MPN_MIN MIN(MPN_MIN_0_to_4, MPN_MIN_5_to_8)
#define MPN_MAX MAX(MPN_MAX_0_to_4, MPN_MAX_5_to_8)
#define MPN_VALID(value)						\
	({								\
		enum mini_protocol_num __ctx_mpn##__LINE__ = (value);	\
		__ctx_mpn##__LINE__ >= MPN_MIN &&			\
			__ctx_mpn##__LINE__ <= MPN_MAX;			\
	})

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

union sdu_ptr {
	uint32_t *sdu32;
	uint16_t *sdu16;
	uint8_t  *sdu8;
} __attribute__((packed,aligned(8)));

int sdu_encode(const struct sdu *, union sdu_ptr);
int sdu_decode(const union sdu_ptr, struct sdu *);
int sdu_print(const struct sdu *);
const char *mini_protocol_string(enum mini_protocol_num);
