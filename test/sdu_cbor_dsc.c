#include <cbor.h>
#include <inttypes.h>
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
	ssize_t ret;
	int retval = EXIT_FAILURE;
	off_t off;
	uint64_t sdu_data;
	union sdu_ptr sdu_buf = { .sdu8 = (uint8_t *)&sdu_data, };

	if (!(cbor_buf = calloc(1024, 1024))) {
		ctf_msg(cbor_dsc, "calloc() of cbor_buf failed\n");
		return EXIT_FAILURE;
	}
restart_loop:
	if ((off = lseek(STDIN_FILENO, 0, SEEK_CUR)) < 0) {
		ctf_msg(cbor_dsc, "lseek() tell failed, "
				  "errno = %d\n", errno);
		goto exit_free_buf;
	}
	if ((ret = read(STDIN_FILENO, sdu_buf.sdu8, 8)) != 8) {
		if (!!ret || !!errno)
			ctf_msg(cbor_dsc, "SDU header read() failure, "
					  "ret = %d, errno = %d\n",
					  ret, errno);
		else
			retval = EXIT_SUCCESS;
		goto exit_free_buf;
	}
	if (sdu_decode(sdu_buf, &sdu) != RETVAL_SUCCESS) {
		ctf_msg(cbor_dsc, "SDU header sdu_decode() failure\n");
		goto exit_free_buf;
	}
	sdu.sdu_data = (const char *)cbor_buf;
	printf("SDU offset = %jx\n", (intmax_t)off);
	sdu_print(&sdu);
	if (!sdu.sdu_len)
		goto restart_loop;
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
