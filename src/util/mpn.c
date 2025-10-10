#include "mpn.h"

const char *
mini_protocol_string(enum mini_protocol_num mpn)
{
	static char *mpn_string_table[MPN_NR] = {
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
	static char default_string[] = "unrecognized mpn";

	return MPN_VALID(mpn) ? mpn_string_table[mpn] : default_string;
}
