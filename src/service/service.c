#include <cbor.h>
#include <cbor/data.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "c_trace_fwd.h"
#include "ctf_cbor_drv.h"

static int service_relay(struct c_trace_fwd_state *state,
			 struct c_trace_fwd_conf *conf)
{
	int retval = RETVAL_FAILURE;
	unsigned char *buf;
	size_t buf_sz, ret_sz, pos, to_write;
	ssize_t write_ret_sz;

	(void)conf;
	if (!state->item_tbl_pos)
		goto exit_failure;
	ret_sz = cbor_serialize_alloc(state->item_tbl[state->item_tbl_pos - 1],
				      &buf, &buf_sz);
	if (!ret_sz)
		goto exit_failure;
	pos = 0;
	to_write = ret_sz;
	while (to_write > 0) {
		write_ret_sz = write(state->ux_sock_fd, &buf[pos], ret_sz);
		/* If somehow too much was written, there is a bug. */
		if (write_ret_sz > ret_sz)
			goto exit_free;
		if (write_ret_sz < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				goto exit_free;
			errno = 0;
			continue;
		}
		ret_sz -= write_ret_sz;
		pos += write_ret_sz;
	}
	retval = RETVAL_SUCCESS;
exit_free:
	free(buf);
exit_failure:
	return retval;
}

int service_loop(struct c_trace_fwd_state *state, struct c_trace_fwd_conf *conf)
{
	int retval = RETVAL_FAILURE;

	while (1) {
		char *buf = calloc(1024, 1024);
		ssize_t bytes_returned;
		size_t bytes_to_decode;
		cbor_data cbor_buf;
		struct cbor_decoder_result result;

retry_read:
		bytes_returned = read(state->unix_sock_fd, buf, 1024 * 1024);
		if (bytes_returned < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				goto exit_failure;
			errno = 0;
			goto retry_read;
		}
		bytes_to_decode = (size_t)bytes_returned;
		cbor_buf = (cbor_data)buf;
		result = cbor_stream_decode(cbor_buf, bytes_to_decode,
					    &ctf_cbor_drv, state /* context */);
		switch (result.status) {
		case CBOR_DECODER_FINISHED:
			service_relay(state, conf);
			/* deliberate fall-through */
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
