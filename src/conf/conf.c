#include <stdlib.h>
#include "c_trace_fwd.h"

int
setup_conf(struct c_trace_fwd_conf **conf, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	*conf = calloc(1, sizeof(struct c_trace_fwd_conf));
	return *conf != NULL ? RETVAL_SUCCESS : RETVAL_FAILURE;
}

void
teardown_conf(struct c_trace_fwd_conf **conf)
{
	free(*conf);
	*conf = NULL;
}
