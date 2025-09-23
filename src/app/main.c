#include <stddef.h>
#include <sys/types.h>
#include <stdlib.h>
#include <getopt.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "service.h"

int main(int argc, char *argv[])
{
	int exit_status = EXIT_FAILURE;
	struct ctf_conf *conf = NULL;
	struct ctf_state *state = NULL;

	if (setup_conf(&conf, argc, argv))
		goto exit_failure;
	if (setup_state(&state, conf))
		goto exit_teardown_conf;
	if (service_loop(state, conf))
		goto exit_teardown_state;
	exit_status = EXIT_SUCCESS;
exit_teardown_state:
	teardown_state(&state);
exit_teardown_conf:
	teardown_conf(&conf);
exit_failure:
	exit(exit_status);
}
