#include <pthread.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"

struct ctf_thread_arg {
	struct c_trace_fwd_conf *conf;
	struct c_trace_fwd_state *state;
};

static void *
service_unix_sock_thread(void *pthread_arg)
{
	struct ctf_thread_arg *arg = pthread_arg;

	(void)!!arg;
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
service_thread_spawn(struct c_trace_fwd_conf *conf,
			struct c_trace_fwd_state *state)
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
