#pragma once

struct datapoint_req {
	int datapoint_nr_req;
	const char **datapoint_req_names;
};

struct datapoint_resp_elem {
	const char *datapoint_resp_name;
	/* can be NULL to represent Haskell Maybe's Nothing case
	 * JSON in CBOR is involved in a constructed value
	 * stub code is never going to try to codec the strings here */
	const char *datapoint_resp_value;
};

struct datapoint_resp {
	/* empty responses will have ->datapoint_nr_resp == 0 */
	int datapoint_nr_resp;
	struct datapoint_resp_elem datapoint_resp_elem;
};

enum datapoint_msg_type {
	datapoint_req,
	datapoint_resp,
};

#define DATAPOINT_MSG_TYPE_MIN MIN(datapoint_req, datapoint_resp)
#define DATAPOINT_MSG_TYPE_MAX MAX(datapoint_req, datapoint_resp)
#define DATAPOINT_MSG_TYPE_VALID(value)					\
	({								\
		enum datapoint_msg_type __ctx_dmt##__LINE__ = (value);	\
		__ctx_dmt##__LINE__ >= DATAPOINT_MSG_TYPE_MIN &&	\
			__ctx_dmt##__LINE__ <= DATAPOINT_MSG_TYPE_MAX;	\
	 })

struct datapoint_msg {
	enum datapoint_msg_type datapoint_msg_type;
	union {
		struct datapoint_req datapoint_req;
		struct datapoint_resp datapoint_resp;
	};
};
