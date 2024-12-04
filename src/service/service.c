#include <stdlib.h>
#include <unistd.h>
#include <cbor.h>
#include "c_trace_fwd.h"

struct cbor_callbacks callbacks = {
	.uint8 = NULL,
	.uint16 = NULL,
	.uint32 = NULL,
	.uint64 = NULL,
	.negint8 = NULL,
	.negint16 = NULL,
	.negint32 = NULL,
	.negint64 = NULL,
	.byte_string_start = NULL,
	.byte_string = NULL,
	.string = NULL,
	.string_start = NULL,
	.indef_array_start = NULL,
	.array_start = NULL,
	.indef_map_start = NULL,
	.map_start = NULL,
	.tag = NULL,
	.float2 = NULL,
	.float4 = NULL,
	.float8 = NULL,
	.undefined = NULL,
	.null = NULL,
	.boolean = NULL,
	.indef_break = NULL,
};

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
		result = cbor_stream_decode((cbor_data)buf, (size_t)bytes_returned, &callbacks, NULL /* context */);
		(void)result;

		if (buf == NULL)
			goto exit_failure;
		free(buf);
	}
	retval = RETVAL_SUCCESS;
exit_failure:
	return retval;
}
