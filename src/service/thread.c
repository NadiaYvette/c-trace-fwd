#include <pthread.h>
#include "agency.h"
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "proto_stk.h"
#include "sdu.h"
#include "service.h"

static bool
service_unix_sock_thread_data_points_reply(struct ctf_conf *conf, struct ctf_state *state)
{
	char *buf;
	size_t size;
	ssize_t send_ret;

	if (!(buf = datapoint_hostname_reply(&size)))
		return false;
	send_ret = write(state->unix_io.fd, buf, size);
	g_rc_box_release(buf);
	if (send_ret < 0)
		return false;
	return send_ret == (ssize_t)size;
}

static bool
service_unix_sock_thread_data_points(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	(void)!!conf;
	(void)!!cpsdr;
	ctf_msg(ctf_debug, thread, "entering\n");
	(void)!datapoint_examine(&cpsdr->proto_stk_decode_result_body->undecoded);
	switch (state->unix_io.agencies[mpn_data_points]) {
	case relative_agency_we_have:
	case relative_agency_nobody_has:
		ctf_set_agency(thread, &state->unix_io,
				relative_agency_they_have, mpn_data_points);
		return service_unix_sock_thread_data_points_reply(conf, state);
	case relative_agency_they_have:
	default:
		/* never make datapoint requests */
		return true;
	}
}

static bool
service_unix_sock_thread_metrics_reply(struct ctf_conf *conf, struct ctf_state *state)
{
	char *buf;
	size_t size;
	ssize_t send_ret;

	if (!(buf = metrics_encode_empty_resp(&size)))
		return false;
	if ((send_ret = write(state->unix_io.fd, buf, size)) < 0)
		return false;
	return send_ret == (ssize_t)size;
}

static bool
service_unix_sock_thread_metrics(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	(void)!!conf;
	(void)!!cpsdr;
	ctf_msg(ctf_debug, thread, "entering\n");
	switch (state->unix_io.agencies[mpn_EKG_metrics]) {
	case relative_agency_we_have:
	case relative_agency_nobody_has:
		ctf_set_agency(thread, &state->unix_io,
				relative_agency_they_have, mpn_EKG_metrics);
		return service_unix_sock_thread_metrics_reply(conf, state);
	case relative_agency_they_have:
	default:
		/* never make requests */
		break;
	}
	return true;
}

static bool
service_unix_sock_thread_trace_objects_local(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	/* if we have or can take initiative, send a request */
	struct tof_msg request_msg = {
		.tof_msg_type = tof_request,
		.tof_msg_body = {
			.request = {
				.tof_blocking = true,
				.tof_nr_obj = 100,
			},
		},
	};
	const char *namespace[] = { [0] = "Tracer.BuildInfo", };
	struct trace_object dummy = {
		.to_human = "dummy trace object (human)",
		.to_machine = "dummy trace object (machine)",
		.to_namespace_nr = 1,
		.to_namespace = &namespace[0],
		.to_severity = severity_debug,
		.to_details = ddetailed,
		.to_timestamp = time(NULL),
		.to_hostname = "nyc-ipad-mini",
		.to_thread_id = "ctf-thread",
	};
	struct trace_object *reply_ary[] = { [0] = &dummy, };
	struct tof_msg empty_reply = {
		.tof_msg_type = tof_reply,
		.tof_msg_body = {
			.reply = {
				.tof_nr_replies = 1,
				.tof_replies = &reply_ary[0],
			},
		},
	};
	struct tof_msg *incoming_msg
		= (struct tof_msg *)cpsdr->proto_stk_decode_result_body;
	struct tof_msg *reply_msg = NULL;

	switch (incoming_msg->tof_msg_type) {
	case tof_reply:
		ctf_msg(ctf_alert, thread, "received tof_reply\n");
		return service_send_tof(state, &request_msg, state->unix_io.fd) == RETVAL_SUCCESS;
	default:
		ctf_msg(ctf_alert, thread, "unexpected tof_msg_type\n");
		return false;
	case tof_done:
		ctf_msg(ctf_alert, thread, "received tof_done\n");
		return true;
	case tof_request:
		struct tof_request *request;
		request = &incoming_msg->tof_msg_body.request;
		switch (to_queue_answer_request(&state->unix_io.out_queue, request, &reply_msg)) {
		case svc_req_success:
			ctf_msg(ctf_alert, thread, "svc_req_success\n");
			return true;
		case svc_req_must_block:
		case svc_req_none_available:
			ctf_msg(ctf_debug, thread, "must_block/none_available\n");
			return service_send_tof(state, &empty_reply, state->unix_io.fd) == RETVAL_SUCCESS;
		case svc_req_failure:
		default:
			ctf_msg(ctf_alert, thread, "svc_req_failure\n");
			return false;
		}
	}
}

static bool
service_unix_sock_thread_trace_objects(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	(void)!!conf;
	switch (state->unix_io.agencies[mpn_trace_objects]) {
	case relative_agency_we_have:
	case relative_agency_nobody_has:
		ctf_set_agency(thread, &state->unix_io,
				relative_agency_they_have, mpn_trace_objects);
		return service_unix_sock_thread_trace_objects_local(conf, state, cpsdr);
	case relative_agency_they_have:
		ctf_msg(ctf_alert, thread, "they have agency\n");
		break;
	default:
		/* relaying user socket data goes here */
		ctf_msg(ctf_alert, thread, "unexpected agency\n");
		break;
	}
	return true;
}

/*
 * 1: all agencies idle (nobody) or remote
 * 2: some agencies local i.e. response demanded
 * 3: SDU header received, awaiting payload
 * 4: blocked in packet send
 */
static bool
service_unix_sock_thread_core(struct ctf_conf *conf, struct ctf_state *state)
{
	int retval = false;
	struct ctf_proto_stk_decode_result *cpsdr;
	enum mini_protocol_num mpn;

	(void)!!conf;
	ctf_msg(ctf_debug, thread, "entered\n");
	io_queue_show_agencies(&state->unix_io);
	if (!(cpsdr = ctf_proto_stk_decode(state->unix_io.fd))) {
		ctf_msg(ctf_debug, thread, "ctf_proto_stk_decode() failed\n");
		return false;
	} else
		ctf_msg(ctf_debug, thread, "cpsdr = %p\n", cpsdr);
	mpn = cpsdr->sdu.sdu_proto_un.sdu_proto_num;
	if (MPN_VALID(mpn))
		ctf_set_agency(thread, &state->unix_io, relative_agency_we_have, mpn);
	switch (mpn) {
	case mpn_data_points:
		if (!service_unix_sock_thread_data_points(conf, state, cpsdr))
			goto out_free_cpsdr;
		break;
	case mpn_EKG_metrics:
		if (!service_unix_sock_thread_metrics(conf, state, cpsdr))
			goto out_free_cpsdr;
		break;
	case mpn_trace_objects:
		if (!service_unix_sock_thread_trace_objects(conf, state, cpsdr))
			goto out_free_cpsdr;
		break;
	default:
		ctf_msg(ctf_alert, thread, "unrecognized protocol %s\n",
				mini_protocol_string(mpn));
		break;
	}
	retval = true;
out_free_cpsdr:
	cpsdr_free(cpsdr);
	return retval;
}

static void *
service_unix_sock_thread(void *pthread_arg)
{
	struct ctf_thread_arg *arg = pthread_arg;
	struct ctf_conf *conf;
	struct ctf_state *state;
	struct tof_msg request_msg = {
		.tof_msg_type = tof_request,
		.tof_msg_body = {
			.request = {
				.tof_blocking = true,
				.tof_nr_obj = 100,
			},
		},
	};

	if (!arg)
		return NULL;
	conf = arg->conf;
	state = arg->state;
	if (!conf || !state)
		return NULL;
	if (0) {
		ctf_msg(ctf_debug, thread, "sending initial request\n");
		if (service_send_tof(state, &request_msg, state->unix_io.fd) != RETVAL_SUCCESS) {
			ctf_msg(ctf_debug, thread, "sending initial request failed\n");
			return NULL;
		}
		ctf_msg(ctf_debug, thread, "back from sending initial request\n");
	}
	ctf_set_agency(thread, &state->unix_io,
				relative_agency_they_have, mpn_trace_objects);
	for (;;) {
		bool ret;

		if (!!pthread_mutex_lock(&state->state_lock)) {
			ctf_msg(ctf_alert, thread,
					"locking state failed!\n");
			break;
		}
		ret = service_unix_sock_thread_core(conf, state);
		if (!!pthread_mutex_unlock(&state->state_lock)) {
			ctf_msg(ctf_alert, thread,
					"unlocking state failed!\n");
			break;
		}
		if (ret)
			continue;
		ctf_msg(ctf_alert, thread,
			"service_unix_sock_thread_core() failed!\n");
		break;
	}
	return NULL;
}

static void *
service_user_sock_thread(void *pthread_arg)
{
	struct ctf_thread_arg *arg = pthread_arg;

	(void)!!arg;
	return NULL;
}

bool
service_thread_spawn(struct ctf_conf *conf, struct ctf_state *state)
{
	pthread_t unix_thread, user_thread;
	pthread_attr_t attr;
	struct ctf_thread_arg *ctf_thread_arg;

	if (!(ctf_thread_arg = g_rc_box_new0(struct ctf_thread_arg)))
		return false;
	ctf_thread_arg->conf = conf;
	ctf_thread_arg->state = state;
	if (!!pthread_attr_init(&attr))
		goto out_free_arg;
	if (!!pthread_create(&unix_thread, &attr, service_unix_sock_thread, ctf_thread_arg))
		goto out_destroy_attr;
	if (!!pthread_create(&user_thread, &attr, service_user_sock_thread, ctf_thread_arg))
		goto out_cancel_unix_thread;
	if (!!pthread_attr_destroy(&attr))
		ctf_msg(ctf_alert, thread,
				"pthread_attr_destroy() failed\n");
	return true;
out_cancel_unix_thread:
	if (!!pthread_cancel(unix_thread))
		ctf_msg(ctf_alert, thread, "pthread_cancel() failed!\n");
out_destroy_attr:
	if (!!pthread_attr_destroy(&attr))
		ctf_msg(ctf_alert, thread,
				"pthread_attr_destroy() failed\n");
out_free_arg:
	g_rc_box_release(ctf_thread_arg);
	return false;
}
