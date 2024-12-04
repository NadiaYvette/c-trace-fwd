#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "c_trace_fwd.h"

static void
copy_optarg(struct sockaddr_un *unix_sock, const char *s)
{
	strncpy(unix_sock->sun_path, s, sizeof(unix_sock->sun_path));
}

int
setup_conf(struct c_trace_fwd_conf **conf, int argc, char *argv[])
{
	int opt, retval = RETVAL_FAILURE;

	*conf = calloc(1, sizeof(struct c_trace_fwd_conf));
	if (*conf == NULL)
		goto exit_failure;
	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
		case 'f':
			copy_optarg(&(*conf)->unix_sock, optarg);
			break;
		default:
			fprintf(stderr, "c_trace_fwd: unrecognized "
					"option\n");
			fprintf(stderr, "unrecognized option character "
					"\'%c\'\n", (char)opt);
			fprintf(stderr, "optind = %d\n", optind);
			goto exit_cleanup;
			break;
		}
	}
	retval = RETVAL_SUCCESS;
	return retval;
exit_cleanup:
	free(*conf);
	*conf = NULL;
exit_failure:
	return retval;
}

void
teardown_conf(struct c_trace_fwd_conf **conf)
{
	free(*conf);
	*conf = NULL;
}
