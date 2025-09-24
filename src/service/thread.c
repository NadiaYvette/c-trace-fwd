#include <pthread.h>
#include "agency.h"
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "proto_stk.h"
#include "sdu.h"

struct ctf_thread_arg {
	struct ctf_conf *conf;
	struct ctf_state *state;
};

static bool
service_unix_sock_thread_data_points(struct ctf_conf *conf, struct ctf_state *state)
{
	(void)!!conf;
	(void)!!state;
	return true;
}

static bool
service_unix_sock_thread_metrics(struct ctf_conf *conf, struct ctf_state *state)
{
	(void)!!conf;
	(void)!!state;
	return true;
}

static bool
service_unix_sock_thread_trace_objects(struct ctf_conf *conf, struct ctf_state *state)
{
	(void)!!conf;
	(void)!!state;
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
	ctf_msg(thread, "entered\n");
	if (!(cpsdr = ctf_proto_stk_decode(state->unix_io.fd)))
		goto out_free_cpsdr;
	switch (mpn = cpsdr->sdu.sdu_proto_un.sdu_proto_num) {
	case mpn_data_points:
		if (!service_unix_sock_thread_data_points(conf, state))
			goto out_free_cpsdr;
		break;
	case mpn_EKG_metrics:
		if (!service_unix_sock_thread_metrics(conf, state))
			goto out_free_cpsdr;
		break;
	case mpn_trace_objects:
		if (!service_unix_sock_thread_trace_objects(conf, state))
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
		ret = service_unix_sock_thread_core(conf, state);
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
