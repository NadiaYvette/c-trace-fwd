#include <cbor.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "c_trace_fwd.h"
#include "ctf_util.h"
#include "sdu.h"

int
main(void)
{
	struct sdu sdu;
	union sdu_ptr sdu_buf = { .sdu8 = (uint8_t *)&sdu };
	ssize_t ret;
	off_t cur_off, dst_off;
	struct stat stat_buf;
	int retval = EXIT_FAILURE;
	unsigned char *buf;
	cbor_item_t *item;
	struct cbor_load_result result;

	if (sizeof(sdu_buf) != 8) {
		ctf_msg(ctf_alert, cbor_dissect,
				"SDU header structure size %z "
				     "unexpected\n", sizeof(sdu_buf));
		return EXIT_FAILURE;
	}
	if (!!fstat(STDIN_FILENO, &stat_buf)) {
		ctf_msg(ctf_alert, cbor_dissect,
				"fstat(2) failed, errno = %d\n",
				     errno);
		return EXIT_FAILURE;
	}
	if (!(buf = calloc((size_t)1U << 8, (size_t)1U << 8))) {
		ctf_msg(ctf_alert, cbor_dissect,
				"calloc(3) failed, errno = %d\n",
				errno);
		return EXIT_FAILURE;
	}
	switch (stat_buf.st_mode & S_IFMT) {
	case S_IFBLK:
		ctf_msg(ctf_alert, cbor_dissect,
				"fatal: block device unexpected "
				"as input file\n");
		goto exit_free_buf;
	case S_IFCHR:
		ctf_msg(ctf_alert, cbor_dissect,
				"fatal: character device "
				"unexpected as input file\n");
		goto exit_free_buf;
	case S_IFDIR:
		ctf_msg(ctf_alert, cbor_dissect,
				"fatal: directory unexpected as "
				     "input file\n");
		goto exit_free_buf;
	case S_IFIFO:
		ctf_msg(ctf_alert, cbor_dissect,
				"FIFO unexpected as "
				     "input file\n");
		break;
	case S_IFLNK:
		ctf_msg(ctf_alert, cbor_dissect,
				"symlink unexpected as "
				     "input file\n");
		break;
	case S_IFREG:
		/* This is the expected file type. */
		break;
	case S_IFSOCK:
		ctf_msg(ctf_alert, cbor_dissect,
				"socket unexpected as "
				     "input file\n");
		break;
	default:
		ctf_msg(ctf_alert, cbor_dissect,
				"fatal: undocumented input file "
				"type\n");
		goto exit_free_buf;
	}
restart_loop_from_tell:
	if ((cur_off = lseek(STDIN_FILENO, 0, SEEK_CUR)) < 0) {
		ctf_msg(ctf_alert, cbor_dissect,
				"tell failure, errno = %d\n", errno);
		goto exit_free_buf;
	}
restart_loop:
	if ((ret = read(STDIN_FILENO, buf, 8)) != 8) {
		if (!ret && !errno)
			/* This is the EOF condition. */
			retval = EXIT_SUCCESS;
		else
			ctf_msg(ctf_alert, cbor_dissect,
					"SDU header read() failure, "
					  "ret = %d, errno = %d\n",
					  ret, errno);
		goto exit_free_buf;
	}
	memset(&sdu, 0xc, sizeof(struct sdu));
	sdu_buf.sdu8 = (uint8_t *)buf;
	if (sdu_decode(sdu_buf, &sdu) != RETVAL_SUCCESS) {
		ctf_msg(ctf_alert, cbor_dissect,
				"SDU header sdu_decode() failure\n");
		goto exit_free_buf;
	}
	printf("SDU header at off=0x%jx\n", (intmax_t)cur_off);
	sdu_print(&sdu);
	if (sdu.sdu_len < sizeof(sdu_buf)) {
		ctf_msg(ctf_warning, cbor_dissect,
				"sdu_len < sizeof(struct sdu), "
				     "trying to keep going anyway\n");
		if (0)
			goto restart_loop_from_tell;
		ctf_msg(ctf_warning, cbor_dissect,
				"omitting recovery attempt; "
				     "it may merely reflect a small datum\n");
	}
	/* The tell was done before the read. */
	dst_off = cur_off + sdu.sdu_len + 8;
	if (dst_off > stat_buf.st_size) {
		ctf_msg(ctf_alert, cbor_dissect,
				"sdu_len runs past EOF, "
				"dst_off = 0x%jx, "
				"st_size = 0x%jx\n",
				(intmax_t)dst_off,
				(intmax_t)stat_buf.st_size);
		goto exit_free_buf;
	}
	if ((ret = read(STDIN_FILENO, buf, sdu.sdu_len)) != (ssize_t)sdu.sdu_len || ret <= 0) {
		ctf_msg(ctf_alert, cbor_dissect,
				"read failure, errno = %d, "
				      "ret = 0x%zx, "
				      "sdu_len = "PRIx16"\n",
				      errno, ret, sdu.sdu_len);
		goto exit_free_buf;
	}
	cur_off = lseek(STDIN_FILENO, 0, SEEK_CUR);
	if (cur_off != dst_off) {
		ctf_msg(ctf_alert, cbor_dissect,
				"short read or offset mis-match"
				     "/calculation, "
				     "ret = 0x%zx, "
				     "dst_off = 0x%jx, "
				     "cur_off = 0x%jx\n",
				     ret, (intmax_t)dst_off, (intmax_t)cur_off);
		if (0)
			goto exit_free_buf;
	}
	if (!(item = cbor_load(buf, sdu.sdu_len, &result))) {
		ctf_msg(ctf_alert, cbor_dissect,
				"cbor_load failure, errno = %d\n",
				      errno);
		goto exit_free_buf;
	}
	cbor_describe(item, stdout);
	ctf_cbor_decref(cbor_dissect, &item);
	goto restart_loop;
	retval = EXIT_SUCCESS;
exit_free_buf:
	free(buf);
	return retval;
}
