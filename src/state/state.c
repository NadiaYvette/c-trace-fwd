#include <stdlib.h>
#include "c_trace_fwd.h"

int
setup_state(struct c_trace_fwd_state **state, struct c_trace_fwd_conf *conf)
{
	(void)conf;
	*state = calloc(1, sizeof(struct c_trace_fwd_state));
	return *state != NULL ? RETVAL_SUCCESS : RETVAL_FAILURE;
}

void
teardown_state(struct c_trace_fwd_state **state)
{
	free(*state);
	*state = NULL;
}
