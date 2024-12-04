#include <stdlib.h>
#include <unistd.h>
#include <cbor.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv.h"

int
service_loop(struct c_trace_fwd_state *state, struct c_trace_fwd_conf *conf)
{
	int retval = RETVAL_FAILURE;

	(void)conf;
	while (1) {
		char *buf = calloc(1024, 1024);
		ssize_t bytes_returned;
		struct cbor_decoder_result result;

		bytes_returned = read(state->unix_sock_fd, buf, 1024*1024);
		result = cbor_stream_decode((cbor_data)buf, (size_t)bytes_returned, &ctf_cbor_drv, NULL /* context */);
		(void)result;

		if (buf == NULL)
			goto exit_failure;
		free(buf);
	}
	retval = RETVAL_SUCCESS;
exit_failure:
	return retval;
}
