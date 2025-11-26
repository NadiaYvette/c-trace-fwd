#pragma once

#include <stddef.h>

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
	datapoint_req  = 0,
	datapoint_resp = 1,
	datapoint_done = 2,
};

#define DATAPOINT_MSG_TYPE_MIN						\
		MIN(datapoint_req, MIN(datapoint_done, datapoint_resp))
#define DATAPOINT_MSG_TYPE_MAX						\
		MAX(datapoint_req, MAX(datapoint_done, datapoint_resp))
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

struct cbor_item_t;
struct cbor_item_t *build_empty_datapoint_resp(void);
void *datapoint_encode_empty_resp(size_t *);
struct cbor_item_t *datapoint_hostname_reply_cbor(void);
char *datapoint_hostname_reply(size_t *);
bool datapoint_examine(struct cbor_item_t *);
