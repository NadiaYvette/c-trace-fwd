#include <stdlib.h>
#include <unistd.h>
#include <cbor.h>
#include <cbor/data.h>
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
		size_t bytes_to_decode;
		struct cbor_decoder_result result;

		bytes_returned = read(state->unix_sock_fd, buf, 1024*1024);
		if (bytes_returned < 0)
			goto exit_failure;
		bytes_to_decode = (size_t)bytes_returned;
		result = cbor_stream_decode((cbor_data)buf, bytes_to_decode, &ctf_cbor_drv, state /* context */);
		switch (result.status) {
		case CBOR_DECODER_FINISHED:
		case CBOR_DECODER_NEDATA:
			/* break the switch, not loop */
			break;
		case CBOR_DECODER_ERROR:
			goto exit_failure;
		}

		if (buf == NULL)
			goto exit_failure;
		free(buf);
	}
	retval = RETVAL_SUCCESS;
exit_failure:
	return retval;
}
