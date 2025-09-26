#include <pthread.h>
#include "agency.h"
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "proto_stk.h"
#include "sdu.h"
#include "service.h"

struct ctf_thread_arg {
	struct ctf_conf *conf;
	struct ctf_state *state;
};

static bool
service_unix_sock_thread_data_points(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	(void)!!conf;
	switch (state->unix_io.agencies[mpn_data_points]) {
	case agency_local:
		/* demanded replies sent elsewhere */
		ctf_msg(thread, "unexpected agency\n");
		break;
	case agency_remote:
	case agency_nobody:
	default:
		/* never make requests */
		break;
	}
	return true;
}

static bool
service_unix_sock_thread_metrics(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	(void)!!conf;
	switch (state->unix_io.agencies[mpn_EKG_metrics]) {
	case agency_local:
		/* demanded replies sent elsewhere */
		ctf_msg(thread, "unexpected agency\n");
		break;
	case agency_remote:
	case agency_nobody:
	default:
		/* never make requests */
		break;
	}
	return true;
}

static bool
service_unix_sock_thread_trace_objects(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	(void)!!conf;
	switch (state->unix_io.agencies[mpn_trace_objects]) {
	case agency_local:
		/* demanded replies sent elsewhere */
		ctf_msg(thread, "unexpected agency\n");
		break;
	case agency_remote:
	case agency_nobody:
	default:
		/* relaying user socket data goes here */
		break;
	}
	return true;
}

static bool
service_unix_reply_datapoint(struct ctf_conf *conf, struct ctf_state *state)
{
	char *buf;
	size_t size;
	ssize_t send_ret;

	if (!(buf = datapoint_encode_empty_resp(&size)))
		return false;
	if ((send_ret = send(state->unix_io.fd, buf, size, MSG_NOSIGNAL)) < 0)
		return false;
	return send_ret == (ssize_t)size;
}

static bool
service_unix_reply_metric(struct ctf_conf *conf, struct ctf_state *state)
{
	char *buf;
	size_t size;
	ssize_t send_ret;

	if (!(buf = metrics_encode_empty_resp(&size)))
		return false;
	if ((send_ret = send(state->unix_io.fd, buf, size, MSG_NOSIGNAL)) < 0)
		return false;
	return send_ret == (ssize_t)size;
}

static bool
service_unix_reply_tof(struct ctf_conf *conf, struct ctf_state *state, struct ctf_proto_stk_decode_result *cpsdr)
{
	struct tof_msg *reply_msg = NULL;
	struct tof_msg *tof_msg;
	struct tof_request *request;

	if (!cpsdr)
		return false;
	if (!cpsdr->proto_stk_decode_result_body)
		return false;
	tof_msg = &cpsdr->proto_stk_decode_result_body->tof_msg;
	request = &tof_msg->tof_msg_body.request;
	if (to_queue_answer_request(&state->unix_io.out_queue, request, &tof_msg) != svc_req_success)
		return false;
	return service_send_tof(state, reply_msg, state->unix_io.fd) == RETVAL_SUCCESS;
}

static bool
service_unix_sock_send_local(struct ctf_conf *conf, struct ctf_state *state)
{
	enum mini_protocol_num mpn;

	for (mpn = MPN_MIN; mpn <= MPN_MAX; ++mpn) {
		if (!MPN_VALID(mpn))
			continue;
		if (state->unix_io.agencies[mpn - MPN_MIN] == agency_local)
			goto out_send_local;
	}
	return false;
out_send_local:
	switch (mpn) {
	case mpn_data_points:
		return service_unix_reply_datapoint(conf, state);
	case mpn_EKG_metrics:
		return service_unix_reply_metric(conf, state);
	case mpn_trace_objects:
		return service_unix_reply_tof(conf, state, (struct ctf_proto_stk_decode_result *)NULL);
	default:
		return false;
	}
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
	ctf_msg(thread, "entered\n");
	if (!(cpsdr = ctf_proto_stk_decode(state->unix_io.fd)))
		goto out_free_cpsdr;
	switch (mpn = cpsdr->sdu.sdu_proto_un.sdu_proto_num) {
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
		ctf_msg(thread, "unrecognized protocol %s\n",
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

	if (!arg)
		return NULL;
	conf = arg->conf;
	state = arg->state;
	if (!conf || !state)
		return NULL;
	for (;;) {
		bool ret;

		if (!!pthread_mutex_lock(&state->state_lock)) {
			ctf_msg(thread, "locking state failed!\n");
			break;
		}
		if (io_queue_agency_all_nonlocal(&state->unix_io))
			ret = service_unix_sock_thread_core(conf, state);
		else
			ret = service_unix_sock_send_local(conf, state);
		if (!!pthread_mutex_unlock(&state->state_lock)) {
			ctf_msg(thread, "unlocking state failed!\n");
			break;
		}
		if (ret)
			continue;
		ctf_msg(thread, "service_unix_sock_thread_core() failed!\n");
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
service_thread_spawn(struct ctf_conf *conf,
			struct ctf_state *state)
{
	pthread_t unix_thread, user_thread;
	pthread_attr_t attr;
	struct ctf_thread_arg arg = {
		.conf = conf,
		.state = state,
	};

	if (!!pthread_attr_init(&attr))
		return false;
	if (!!pthread_attr_destroy(&attr))
		ctf_msg(thread, "pthread_attr_destroy() failed\n");
	if (!!pthread_create(&unix_thread, &attr, service_unix_sock_thread, &arg))
		goto out_destroy_attr;
	if (!!pthread_create(&user_thread, &attr, service_user_sock_thread, &arg))
		goto out_cancel_unix_thread;
	return true;
out_cancel_unix_thread:
	if (!!pthread_cancel(unix_thread))
		ctf_msg(thread, "pthread_cancel() failed!\n");
out_destroy_attr:
	if (!!pthread_attr_destroy(&attr))
		ctf_msg(thread, "pthread_attr_destroy() failed\n");
	return false;
}
