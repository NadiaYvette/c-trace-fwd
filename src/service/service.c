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
		char *buf;
		ssize_t bytes_returned;
		size_t bytes_to_decode, buf_len,
		       buf_chunksz = 1024, buf_chunks = 1024;
		struct cbor_load_result result;
		cbor_data cbor_buf;
		cbor_item_t *item;

		buf_len = buf_chunks * buf_chunksz;
		buf = calloc(buf_chunks, buf_chunksz);
retry_read:
		bytes_returned = read(state->unix_sock_fd, buf, buf_len);
		if (bytes_returned < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				goto exit_failure;
			errno = 0;
			goto retry_read;
		}
		bytes_to_decode = (size_t)bytes_returned;
		cbor_buf = (cbor_data)buf;
		memset(&result, 0, sizeof(struct cbor_load_result));
		item = cbor_load(cbor_buf, bytes_to_decode, &result);
		ctf_stk_push(state, item);
		ctf_tbl_push(state, item);
		switch (result.error.code) {
		case CBOR_ERR_NONE:
			service_relay(state, conf);
			/* deliberate fall-through */
		case CBOR_ERR_NOTENOUGHDATA:
			/* break the switch, not loop */
			break;
		case CBOR_ERR_NODATA:
		case CBOR_ERR_MALFORMATED:
		case CBOR_ERR_MEMERROR:
		case CBOR_ERR_SYNTAXERROR:
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
