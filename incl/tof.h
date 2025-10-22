#pragma once

#include <cbor.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/time.h>

/* Trace Objects and subsidiary enums */
enum severity_s {
	severity_debug = 0,
	severity_info = 1,
	severity_notice = 2,
	severity_warning = 3,
	severity_error = 4,
	severity_critical = 5,
	severity_alert = 6,
	severity_emergency = 7
};

enum detail_level {
	dminimal = 0,
	dnormal = 1,
	ddetailed = 2,
	dmaximum = 3
};

struct trace_object {
	/* unclear how Maybe Text is represented */
	const char *to_human;
	const char *to_machine;
	const char **to_namespace;
	int to_namespace_nr;
	enum severity_s to_severity;
	enum detail_level to_details;
	/* needs to be 64-bit */
	time_t to_timestamp;
	const char *to_hostname;
	const char *to_thread_id;
};

/* Trace Object Forward */
struct tof_request {
	bool tof_blocking;
	uint16_t tof_nr_obj;
};

/* XXX: Are these the right reply array components? */
struct tof_reply {
	int tof_nr_replies;
	struct trace_object **tof_replies;
};

enum tof_msg_type {
	tof_request = 1,
	tof_done = 2,
	tof_reply = 3
};

#define TOF_MSG_TYPE_MIN MIN(tof_request, MIN(tof_done, tof_reply))
#define TOF_MSG_TYPE_MAX MAX(tof_request, MAX(tof_done, tof_reply))
#define TOF_MSG_TYPE_VALID(value)					\
	({								\
		enum tof_msg_type __ctx_tmt##__LINE__ = (value);	\
		__ctx_tmt##__LINE__ >= TOF_MSG_TYPE_MIN &&		\
			__ctx_tmt##__LINE__ <= TOF_MSG_TYPE_MAX;	\
	})


struct tof_msg {
	enum tof_msg_type tof_msg_type;
	union {
		struct tof_request request;
		struct tof_reply reply;
	} tof_msg_body;
};

cbor_item_t *tof_encode(const struct tof_msg *);
struct tof_msg *tof_decode(const cbor_item_t *);
void tof_free(struct tof_msg *);
void trace_object_free(struct trace_object *);
struct trace_object *trace_object_decode(const cbor_item_t *);
cbor_item_t *trace_object_encode(const struct trace_object *);
const char *tof_msg_type_string(enum tof_msg_type);
bool cbor_strdup_array_get(const char **, const cbor_item_t *, unsigned);
bool cbor_bytestrdup_array_get(const char **, size_t *, const cbor_item_t *, unsigned);

enum svc_result;
struct ctf_state;
enum svc_result service_unix_sock_send_empty_reply(struct ctf_state *, int);
