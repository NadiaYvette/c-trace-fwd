#include <cbor.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "sdu.h"

int
main(void)
{
	cbor_item_t *item;
	struct cbor_load_result cbor_load_result;
	struct sdu sdu;
	unsigned char *cbor_buf;
	union {
		char chars[8];
		uint32_t ints[2];
	} sdu_buf;
	ssize_t ret;
	int retval = EXIT_FAILURE;

	if (!(cbor_buf = calloc(1024, 1024))) {
		ctf_msg(cbor_dsc, "calloc() of cbor_buf failed\n");
		return EXIT_FAILURE;
	}
restart_loop:
	if ((ret = read(STDIN_FILENO, sdu_buf.chars, 8)) != 8) {
		if (!!ret || !!errno)
			ctf_msg(cbor_dsc, "SDU header read() failure, "
					  "ret = %d, errno = %d\n",
					  ret, errno);
		else
			retval = EXIT_SUCCESS;
		goto exit_free_buf;
	}
	if (sdu_decode(sdu_buf.ints, &sdu) != RETVAL_SUCCESS) {
		ctf_msg(cbor_dsc, "SDU header sdu_decode() failure\n");
		goto exit_free_buf;
	}
	sdu.sdu_data = (const char *)cbor_buf;
	sdu_print(&sdu);
	if ((ret = read(STDIN_FILENO, cbor_buf, sdu.sdu_len)) != sdu.sdu_len) {
		if (!!ret || !!errno)
			ctf_msg(cbor_dsc, "CBOR payload read() failure, "
					  "ret = %d, errno = %d\n",
					  ret, errno);
		else
			retval = EXIT_SUCCESS;
		goto exit_free_buf;
	}
	if (!(item = cbor_load(cbor_buf, sdu.sdu_len - 8, &cbor_load_result))) {
		ctf_msg(cbor_dsc, "CBOR decode (load) from buffer failed\n");
		goto exit_free_buf;
	}
	cbor_describe(item, stdout);
	cbor_decref(&item);
	goto restart_loop;
exit_free_buf:
	free(cbor_buf);
	return retval;
}
