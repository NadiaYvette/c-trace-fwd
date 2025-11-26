#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "service.h"

static struct ctf_thread_arg ctf_data = {
	.conf = NULL,
	.state = NULL,
};

static void
teardown_ctf_data(void)
{
	teardown_state(&ctf_data.state);
	teardown_conf(&ctf_data.conf);
}

int main(int argc, char *argv[])
{
	signal(SIGPIPE, SIG_IGN);
	if (setup_conf(&ctf_data.conf, argc, argv))
		goto exit_failure;
	if (setup_state(&ctf_data.state, ctf_data.conf))
		goto exit_teardown_conf;
	if (service_loop(ctf_data.state, ctf_data.conf))
		goto exit_teardown_state;
	if (!atexit(teardown_ctf_data))
		pthread_exit(NULL);
exit_teardown_state:
	teardown_state(&ctf_data.state);
exit_teardown_conf:
	teardown_conf(&ctf_data.conf);
exit_failure:
	exit(EXIT_FAILURE);
}
