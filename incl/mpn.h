#pragma once
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

const char *mini_protocol_string(enum mini_protocol_num);
