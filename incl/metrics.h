#pragma once

#include <inttypes.h>
#include <stdint.h>

struct metrics_get_metrics {
	unsigned metrics_nr_metrics;
	const char **metrics_names;
};

enum metrics_req_type {
	metrics_get_all,
	metrics_get_metrics,
	metrics_get_updated,
};

struct metrics_req {
	enum metrics_req_type metrics_req_type;
	struct metrics_get_metrics metrics_get_metrics;
};

enum metrics_value_type {
	metrics_value_counter,
	metrics_value_gauge,
	metrics_value_label,
};

#define METRICS_VALUE_TYPE_MIN						\
	MIN(metrics_value_counter,MIN(metrics_value_gauge,metrics_value_label))
#define METRICS_VALUE_TYPE_MAX						\
	MAX(metrics_value_counter,MAX(metrics_value_gauge,metrics_value_label))
#define METRICS_VALUE_TYPE_VALID(value)					\
	({								\
		enum metrics_value_type __ctx_mvt##__LINE__ = (value);	\
		__ctx_mvt##__LINE__ >= METRICS_VALUE_TYPE_MIN &&	\
			__ctx_mvt##__LINE__ <= METRICS_VALUE_TYPE_MAX;	\
	})

struct metrics_value {
	enum metrics_value_type metrics_value_type;
	union {
		int64_t metrics_value_counter;
		int64_t metrics_value_gauge;
		const char *metrics_value_label;
	} metrics_value_value;
};

struct metrics_resp_elem {
	const char *metrics_resp_name;
	struct metrics_value metrics_resp_value;
};

struct metrics_resp {
	unsigned metrics_nr_resp;
	struct metrics_resp_elem *metrics_resp_metrics;
};

/* a done msg is an empty resp
 * array w/len 1 contains only a type tag
 * this may complicate sending empty replies */
enum metrics_msg_type {
	metrics_req  = 0,
	metrics_resp = 1,
};

#define METRICS_MSG_TYPE_MIN MIN(metrics_req, metrics_resp)
#define METRICS_MSG_TYPE_MAX MAX(metrics_req, metrics_resp)
#define METRICS_MSG_TYPE_VALID(value)					\
        ({                                                              \
                enum metrics_msg_type __ctx_mmt##__LINE__ = (value);	\
		__ctx_mmt##__LINE__ >= METRICS_MSG_TYPE_MIN &&		\
			__ctx_mmt##__LINE__ <= METRICS_MSG_TYPE_MAX;	\
	})

struct metrics_msg {
	enum metrics_msg_type metrics_msg_type;
	union {
		struct metrics_resp metrics_resp;
		struct metrics_req metrics_req;
	} metrics_msg_body;
};

struct cbor_item_t;
struct cbor_item_t *build_empty_metrics_resp(void);
void *metrics_encode_empty_resp(size_t *);
